rule softcnapp_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         836104008bc183610800c74104
         // 00414f97: and ds:[ecx+0x4], 0x0
         // 00414f9b: mov eax, ecx
         // 00414f9d: and ds:[ecx+0x8], 0x0
         // 00414fa1: mov ds:[ecx+0x4], 0x45a3c0
      [-]000033c0c3
         // 00415448: xor eax, eax
         // 0041544a: retn 
      [-]33c03905
         // 00415d6a: xor eax, eax
         // 00415d6c: cmp ds:[0x6073ec], eax
      [-]0f94c0c3
         // 00415d72: setz b1 al
         // 00415d75: retn 
      [-]3bf37318
         // 00415d8e: cmp esi, ebx
         // 00415d90: jnb 0x415daa
      [-]8b3e85ff7409
         // 0046affc: mov edi, ds:[esi]
         // 0046affe: test edi, edi
         // 0046b000: jz 0x46b00b
      [-]ffffffd7
         // 00415da0: call edi
      [-]83c6043bf372ea
         // 0046b00b: add esi, 0x4
         // 0046b00e: cmp esi, ebx
         // 0046b010: jb 0x46affc
      [-]3bf37318
         // 00415db9: cmp esi, ebx
         // 00415dbb: jnb 0x415dd5
      [-]8b3e85ff7409
         // 0046b027: mov edi, ds:[esi]
         // 0046b029: test edi, edi
         // 0046b02b: jz 0x46b036
      [-]ffffffd7
         // 00415dcb: call edi
      [-]83c6043bf372ea
         // 0046b036: add esi, 0x4
         // 0046b039: cmp esi, ebx
         // 0046b03b: jb 0x46b027
      [-]558bec56
         // 004173e0: push ebp
         // 004173e1: mov ebp, esp
         // 004173e3: push esi
      [-]8bf083c40485f6
         // 004173ec: mov esi, eax
         // 004173ee: add esp, 0x4
         // 004173f1: test esi, esi
      [-]558bec8b450885c07502
         // 0050dd90: push ebp
         // 0050dd91: mov ebp, esp
         // 0050dd93: mov eax, ss:[ebp+0x8]
         // 0050dd96: test eax, eax
         // 0050dd98: jnz 0x50dd9c
      [-]8b480485c97409
         // 0050dd9c: mov ecx, ds:[eax+0x4]
         // 0050dd9f: test ecx, ecx
         // 0050dda1: jz 0x50ddac
      [-]8bc18b480485c975f7
         // 0050dda3: mov eax, ecx
         // 0050dda5: mov ecx, ds:[eax+0x4]
         // 0050dda8: test ecx, ecx
         // 0050ddaa: jnz 0x50dda3
      [-]0033c58945fc8b45088985
         // 0041710e: xor eax, ebp
         // 00417110: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00417113: mov eax, ss:[ebp+0x8]
         // 00417116: mov ss:[ebp+0xfffffffffffffbdc], eax
      [-]6a008985
         // 00417136: push 0x0
         // 00417138: mov ss:[ebp+0xfffffffffffffbe0], eax
      [-]6a018985
         // 0041714f: push 0x1
         // 00417151: mov ss:[ebp+0xfffffffffffffbc8], eax
      [-]8b4dfc33cde8
         // 0041751e: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00417521: xor ecx, ebp
         // 00417523: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 00417528: mov esp, ebp
         // 0041752a: pop ebp
         // 0041752b: retn 
      [-]80f90975
         // 004be805: cmp b1 cl, b1 0x9
         // 004be808: jnz 0x4be812
      [-]8a4e014684c975ee
         // 0050de8a: mov b1 cl, b1 ds:[esi+0x1]
         // 0050de8d: inc esi
         // 0050de8e: test b1 cl, b1 cl
         // 0050de90: jnz 0x50de80
      [-]83c41083f8010f8c
         // 005095d3: add esp, 0x10
         // 005095d6: cmp eax, 0x1
         // 005095d9: jl 0x509905
      [-]84c075f9
         // 0050dee9: test b1 al, b1 al
         // 0050deeb: jnz 0x50dee6
      [-]83c40885c0
         // 004176d7: add esp, 0x8
         // 004176da: test eax, eax
      [-]83c40885c074
         // 005097e8: add esp, 0x8
         // 005097eb: test eax, eax
         // 005097ed: jz 0x509804
      [-]8d70018a0684c074
         // 0050e204: lea esi, ds:[eax+0x1]
         // 0050e207: mov b1 al, b1 ds:[esi]
         // 0050e209: test b1 al, b1 al
         // 0050e20b: jz 0x50e220
      [-]3c207404
         // 0050e210: cmp b1 al, b1 0x20
         // 0050e212: jz 0x50e218
      [-]3c097508
         // 0050e214: cmp b1 al, b1 0x9
         // 0050e216: jnz 0x50e220
      [-]8a46014684c075f0
         // 0050e218: mov b1 al, b1 ds:[esi+0x1]
         // 0050e21b: inc esi
         // 0050e21c: test b1 al, b1 al
         // 0050e21e: jnz 0x50e210
      [-]83c40885c0750d
         // 0050e2a7: add esp, 0x8
         // 0050e2aa: test eax, eax
         // 0050e2ac: jnz 0x50e2bb
      [-]0083c408eb0e
         // 004179a6: add esp, 0x8
         // 004179a9: jmp 0x4179b9
      [-]8bf085f674
         // 004bedd1: mov esi, eax
         // 004bedd3: test esi, esi
         // 004bedd5: jz 0x4bee0f
      [-]468d460150ff15
         // 004179c5: inc esi
         // 004179c6: lea eax, ds:[esi+0x1]
         // 004179c9: push eax
         // 004179ca: call ds:[0x605c04]
      [-]83c40489
         // 004179d0: add esp, 0x4
         // 004179d3: mov ds:[ebx+0xc], eax
      [-]0c85c074
         // 004179d6: test eax, eax
         // 004179d8: jz 0x4179f3
      [-]83c40c85c075
         // 005a4e1d: add esp, 0xc
         // 005a4e20: test eax, eax
         // 005a4e22: jnz 0x5a4e2b
      [-]803e230f84
         // 004bee5a: cmp b1 ds:[esi], b1 0x23
         // 004bee5d: jz 0x4be7d8
      [-]6a0d56e8
         // 0041695b: push 0xd
         // 0041695d: push esi
         // 0041695e: call _strchr
      [-]83c40885c07403
         // 00416963: add esp, 0x8
         // 00416966: test eax, eax
         // 00416968: jz 0x41696d
      [-]6a0a56e8
         // 0041696d: push 0xa
         // 0041696f: push esi
         // 00416970: call _strchr
      [-]83c40885c07403
         // 00416975: add esp, 0x8
         // 00416978: test eax, eax
         // 0041697a: jz 0x41697f
      [-]83fe060f87
         // 005a4e8d: cmp esi, 0x6
         // 005a4e90: ja def_5A4E96
      [-]83c40489
         // 00417ae0: add esp, 0x4
         // 00417ae3: mov ds:[ebx+0x10], eax
      [-]85c00f85
         // 00417ae6: test eax, eax
         // 00417ae8: jnz def_417AC9
      [-]8a103a11751a
         // 0050e460: mov b1 dl, b1 ds:[eax]
         // 0050e462: cmp b1 dl, b1 ds:[ecx]
         // 0050e464: jnz 0x50e480
      [-]84d27412
         // 0050e466: test b1 dl, b1 dl
         // 0050e468: jz 0x50e47c
      [-]8a50013a5101750e
         // 0050e46a: mov b1 dl, b1 ds:[eax+0x1]
         // 0050e46d: cmp b1 dl, b1 ds:[ecx+0x1]
         // 0050e470: jnz 0x50e480
      [-]83c00283c10284d275e4
         // 0050e472: add eax, 0x2
         // 0050e475: add ecx, 0x2
         // 0050e478: test b1 dl, b1 dl
         // 0050e47a: jnz 0x50e460
      [-]33c0eb05
         // 0050e47c: xor eax, eax
         // 0050e47e: jmp 0x50e485
      [-]1bc083c801
         // 0050e480: sbb eax, eax
         // 0050e482: or eax, 0x1
      [-]04ff7604e8
         // 0050e5d3: push ds:[esi+0x4]
         // 0050e5d6: call 0x51acd0
      [-]83c40885c0
         // 0050e5db: add esp, 0x8
         // 0050e5de: test eax, eax
      [-]83c40885c0
         // 00417d26: add esp, 0x8
         // 00417d29: test eax, eax
      [-]558bec568b750883be
         // 005a57f0: push ebp
         // 005a57f1: mov ebp, esp
         // 005a57f3: push esi
         // 005a57f4: mov esi, ss:[ebp+0x8]
         // 005a57f7: cmp ds:[esi+0x314], 0x0
      [-]ffffff83c404
         // 004bf98f: add esp, 0x4
      [-]6a026a0256e8
         // 00417302: push 0x2
         // 00417304: push 0x2
         // 00417306: push esi
         // 00417307: call 0x423cc0
      [-]0000ffb6
         // 0041730c: push ds:[esi+0x348]
      [-]e8830000
         // 00417318: call 0x4173a0
      [-]83c41485c07443
         // 0041731d: add esp, 0x14
         // 00417320: test eax, eax
         // 00417322: jz 0x417367
      [-]837d0c00741d
         // 0050ed47: cmp ss:[ebp+0xc], 0x0
         // 0050ed4b: jz 0x50ed6a
      [-]85c07413
         // 005a5853: test eax, eax
         // 005a5855: jz 0x5a586a
      [-]ffff83c404c786
         // 005a585d: add esp, 0x4
         // 005a5860: mov ds:[esi+0x428], 0x0
      [-]6a026a0256e8
         // 0041735a: push 0x2
         // 0041735c: push 0x2
         // 0041735e: push esi
         // 0041735f: call 0x423cc0
      [-]837d0c0074
         // 0050ed77: cmp ss:[ebp+0xc], 0x0
         // 0050ed7b: jz 0x50ed9d
      [-]85c9740b
         // 005a5880: test ecx, ecx
         // 005a5882: jz 0x5a588f
      [-]faffff83c404
         // 005a589a: add esp, 0x4
      [-]6a0256e8
         // 0041738d: push 0x2
         // 0041738f: push esi
         // 00417390: call 0x423d00
      [-]000083c4085e5dc3
         // 00417395: add esp, 0x8
         // 00417398: pop esi
         // 00417399: pop ebp
         // 0041739a: retn 
      [-]83c40885
         // 0041850e: add esp, 0x8
         // 00418511: test esi, esi
      [-]83c40485
         // 0041851d: add esp, 0x4
         // 00418520: test edi, edi
      [-]8be55dc3
         // 005a5995: mov esp, ebp
         // 005a5997: pop ebp
         // 005a5998: retn 
      [-]5bb8????????
         // 005a59b6: pop ebx
         // 005a59b8: mov eax, 0x1
      [-]8be55dc3
         // 005a59be: mov esp, ebp
         // 005a59c0: pop ebp
         // 005a59c1: retn 
      [-]558bec8b5508b9
         // 00418670: push ebp
         // 00418671: mov ebp, esp
         // 00418673: mov edx, ss:[ebp+0x8]
         // 00418676: mov ecx, 0x45b484
      [-]5356578b4208bf
         // 0041867b: push ebx
         // 0041867c: push esi
         // 0041867d: push edi
         // 0041867e: mov eax, ds:[edx+0x8]
         // 00418681: mov edi, 0x45b564
      [-]0f45c88b420c85c00f45f88b42
         // 0041868d: cmovnz ecx, eax
         // 00418690: mov eax, ds:[edx+0xc]
         // 00418693: test eax, eax
         // 00418695: cmovnz edi, eax
         // 00418698: mov eax, ds:[edx+0x10]
      [-]85c00f45d8
         // 0041869b: test eax, eax
         // 0041869d: cmovnz ebx, eax
      [-]85c0740a
         // 0050efc6: test eax, eax
         // 0050efc8: jz 0x50efd4
      [-]80382ebe
         // 004175aa: cmp b1 ds:[eax], b1 0x2e
         // 004175ad: mov esi, 0x45a5ec
      [-]7a300051ff7204b9
         // 004175b9: cmp ds:[edx+0x30], 0x0
         // 004175bd: push ecx
         // 004175be: push ds:[edx+0x4]
         // 004175c1: mov ecx, 0x45a568
      [-]ff721c8bc1ff72180f4445
         // 004175cd: push ds:[edx+0x1c]
         // 004175d0: mov eax, ecx
         // 004175d2: push ds:[edx+0x18]
         // 004175d5: cmovz eax, ss:[ebp+0x8]
      [-]00500f444d
         // 004175d9: cmp ds:[edx+0x24], 0x0
         // 004175dd: push eax
         // 004175de: cmovz ecx, ss:[ebp+0x8]
      [-]00575153b9
         // 004175eb: push edi
         // 004175ec: push ecx
         // 004175ed: push ebx
         // 004175ee: mov ecx, 0x45a498
      [-]560f44c15068
         // 004175f3: push esi
         // 004175f4: cmovz eax, ecx
         // 004175f7: push eax
         // 004175f8: push 0x45a5f0
      [-]83c42c5f5e5b5dc3
         // 00417602: add esp, 0x2c
         // 00417605: pop edi
         // 00417606: pop esi
         // 00417607: pop ebx
         // 00417608: pop ebp
         // 00417609: retn 
      [-]558bec8b45088b80
         // 004c07e0: push ebp
         // 004c07e1: mov ebp, esp
         // 004c07e3: mov eax, ss:[ebp+0x8]
         // 004c07e6: mov eax, ds:[eax+0x370]
      [-]558bec8b4d085651e8
         // 004190b0: push ebp
         // 004190b1: mov ebp, esp
         // 004190b3: mov ecx, ss:[ebp+0x8]
         // 004190b6: push esi
         // 004190b7: push ecx
         // 004190b8: call 0x418fd0
      [-]ffffff8bf0ff7614ff761051e8
         // 004190bd: mov esi, eax
         // 004190bf: push ds:[esi+0x14]
         // 004190c2: push ds:[esi+0x10]
         // 004190c5: push ecx
         // 004190c6: call 0x4262c0
      [-]83c410c746????????005e5dc3
         // 004190cb: add esp, 0x10
         // 004190ce: mov ds:[esi+0x14], 0x0
         // 004190d5: pop esi
         // 004190d6: pop ebp
         // 004190d7: retn 
      [-]558bec568b75086a
         // 0050b270: push ebp
         // 0050b271: mov ebp, esp
         // 0050b273: push esi
         // 0050b274: mov esi, ss:[ebp+0x8]
         // 0050b277: push 0x38
      [-]83c41089
         // 0050b28f: add esp, 0x10
         // 0050b292: mov ds:[esi], eax
      [-]00ff750cc7
         // 004192af: push ss:[ebp+0xc]
         // 004192b2: mov ds:[esi+0x10], 0x0
      [-]83c40489
         // 004192bf: add esp, 0x4
         // 004192c2: mov ds:[esi+0x8], eax
      [-]0885c074
         // 004192c5: test eax, eax
         // 004192c7: jz 0x4192d1
      [-]b8????????5e5dc3
         // 0050fbb9: mov eax, 0x1
         // 0050fbbe: pop esi
         // 0050fbbf: pop ebp
         // 0050fbc0: retn 
      [-]fdffff83c40433c05e
         // 004c0b38: add esp, 0x4
         // 004c0b3b: xor eax, eax
         // 004c0b3e: pop esi
      [-]8a064684c075f9
         // 0050fc21: mov b1 al, b1 ds:[esi]
         // 0050fc23: inc esi
         // 0050fc24: test b1 al, b1 al
         // 0050fc26: jnz 0x50fc21
      [-]83c4040b43
         // 0050b367: add esp, 0x4
         // 0050b36a: or eax, ds:[ebx+0xc]
      [-]8d460150
         // 005a678a: lea eax, ds:[esi+0x1]
         // 005a678d: push eax
      [-]83c41085
         // 005a679c: add esp, 0x10
         // 005a679f: test esi, esi
      [-]558bec83ec08568b750883be
         // 005a68f0: push ebp
         // 005a68f1: mov ebp, esp
         // 005a68f3: sub esp, 0x8
         // 005a68f6: push esi
         // 005a68f7: mov esi, ss:[ebp+0x8]
         // 005a68fa: cmp ds:[esi+0x290], 0xffffffffffffffff
      [-]6a026a0356e8
         // 0041836e: push 0x2
         // 00418370: push 0x3
         // 00418372: push esi
         // 00418373: call 0x423cc0
      [-]000083c40c
         // 00418378: add esp, 0xc
      [-]8d45f850e8
         // 005a691c: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 005a691f: push eax
         // 005a6920: call __time64
      [-]75fcff75f8ffb6
         // 005a6925: push ss:[ebp+0xfffffffffffffffc]
         // 005a6928: push ss:[ebp+0xfffffffffffffff8]
         // 005a692b: push ds:[esi+0x290]
      [-]000083c41483
         // 005a6939: add esp, 0x14
         // 005a693c: cmp ds:[esi+0x48], 0x0
      [-]6a0356e8
         // 004183a0: push 0x3
         // 004183a2: push esi
         // 004183a3: call 0x423d00
      [-]000083c408
         // 004183a8: add esp, 0x8
      [-]5e8be55dc3
         // 0050fd9b: pop esi
         // 0050fd9c: mov esp, ebp
         // 0050fd9e: pop ebp
         // 0050fd9f: retn 
      [-]558bec8b4d0833c085c9740c
         // 0050fdc0: push ebp
         // 0050fdc1: mov ebp, esp
         // 0050fdc3: mov ecx, ss:[ebp+0x8]
         // 0050fdc6: xor eax, eax
         // 0050fdc8: test ecx, ecx
         // 0050fdca: jz 0x50fdd8
      [-]0f1f4000
         // 0050fdcc: nop ds:[eax+0x0]
      [-]8b491c4085c975f8
         // 0050fdd0: mov ecx, ds:[ecx+0x1c]
         // 0050fdd3: inc eax
         // 0050fdd4: test ecx, ecx
         // 0050fdd6: jnz 0x50fdd0
      [-]558bec8b4d088b410483e80274
         // 0050fde0: push ebp
         // 0050fde1: mov ebp, esp
         // 0050fde3: mov ecx, ss:[ebp+0x8]
         // 0050fde6: mov eax, ds:[ecx+0x4]
         // 0050fde9: sub eax, 0x2
         // 0050fdec: jz 0x50fdf2
      [-]33c05dc3
         // 0050fdee: xor eax, eax
         // 0050fdf0: pop ebp
         // 0050fdf1: retn 
      [-]ff75108b4118ff750c83c004506a02e8
         // 00419502: push ss:[ebp+0x10]
         // 00419505: mov eax, ds:[ecx+0x18]
         // 00419508: push ss:[ebp+0xc]
         // 0041950b: add eax, 0x4
         // 0041950e: push eax
         // 0041950f: push 0x2
         // 00419511: call 0x427950
      [-]83c4105dc3
         // 00419516: add esp, 0x10
         // 00419519: pop ebp
         // 0041951a: retn 
      [-]558bec83ec088b45
         // 0050fe10: push ebp
         // 0050fe11: mov ebp, esp
         // 0050fe13: sub esp, 0x8
         // 0050fe16: mov eax, ss:[ebp+0x8]
      [-]c700????????
         // 0050fe30: mov ds:[eax], 0x0
      [-]000083c408
         // 004195cb: add esp, 0x8
      [-]3945f80f84
         // 004c0fdb: cmp ss:[ebp+0xfffffffffffffff8], eax
         // 004c0fde: jz 0x4c1077
      [-]8d45fc50
         // 005a6d59: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 005a6d5c: push eax
      [-]83c40885c0
         // 005a6d63: add esp, 0x8
         // 005a6d66: test eax, eax
      [-]8b451433db395dfc8b4dfc
         // 0050ff18: mov eax, ss:[ebp+0x14]
         // 0050ff1b: xor ebx, ebx
         // 0050ff1d: cmp ss:[ebp+0xfffffffffffffffc], ebx
         // 0050ff20: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]0f94c38908
         // 0050ff24: setz b1 bl
         // 0050ff27: mov ds:[eax], ecx
      [-]8bc35b8be55dc3
         // 0050ff2a: mov eax, ebx
         // 0050ff2c: pop ebx
         // 0050ff2d: mov esp, ebp
         // 0050ff2f: pop ebp
         // 0050ff30: retn 
      [-]6a026a03
         // 00419647: push 0x2
         // 00419649: push 0x3
      [-]000083c40c
         // 00419651: add esp, 0xc
      [-]ffff83c4108945fc83
         // 0050ff51: add esp, 0x10
         // 0050ff54: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0050ff57: cmp ds:[edi+0x10], 0x0
      [-]000083c408
         // 00419675: add esp, 0x8
      [-]837dfc0075
         // 0050ff68: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 0050ff6c: jnz 0x50ff88
      [-]8b451483c4048b4dfc
         // 00419684: mov eax, ss:[ebp+0x14]
         // 00419687: add esp, 0x4
         // 0041968a: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]89088bc3
         // 0041968e: mov ds:[eax], ecx
         // 00419690: mov eax, ebx
      [-]5b8be55dc3
         // 00419693: pop ebx
         // 00419694: mov esp, ebp
         // 00419696: pop ebp
         // 00419697: retn 
      [-]8b45148b4dfc
         // 0050ff8a: mov eax, ss:[ebp+0x14]
         // 0050ff8d: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]5f89088bc35b8be55dc3
         // 0050ff91: pop edi
         // 0050ff92: mov ds:[eax], ecx
         // 0050ff94: mov eax, ebx
         // 0050ff96: pop ebx
         // 0050ff97: mov esp, ebp
         // 0050ff99: pop ebp
         // 0050ff9a: retn 
      [-]558bec83ec14a1
         // 00419790: push ebp
         // 00419791: mov ebp, esp
         // 00419793: sub esp, 0x14
         // 00419796: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b450c8b4d088945ec8b45108945f48b45148945f88d45ec68
         // 0041979b: xor eax, ebp
         // 0041979d: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004197a0: mov eax, ss:[ebp+0xc]
         // 004197a3: mov ecx, ss:[ebp+0x8]
         // 004197a6: mov ss:[ebp+0xffffffffffffffec], eax
         // 004197a9: mov eax, ss:[ebp+0x10]
         // 004197ac: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004197af: mov eax, ss:[ebp+0x14]
         // 004197b2: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004197b5: lea eax, ss:[ebp+0xffffffffffffffec]
         // 004197b8: push 0x4197e0
      [-]8b4dfc83c40c33cde8
         // 004197c4: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004197c7: add esp, 0xc
         // 004197ca: xor ecx, ebp
         // 004197cc: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 004197d1: mov esp, ebp
         // 004197d3: pop ebp
         // 004197d4: retn 
      [-]558bec83ec
         // 00518480: push ebp
         // 00518481: mov ebp, esp
         // 00518483: sub esp, 0x8
      [-]d20f9fc18bc1
         // 005184a3: test edx, edx
         // 005184a5: setnle b1 cl
         // 005184a8: mov eax, ecx
      [-]83e80174
         // 005184ba: sub eax, 0x1
         // 005184bd: jz 0x5184eb
      [-]83e80174
         // 005184bf: sub eax, 0x1
         // 005184c2: jz 0x5184e3
      [-]83e80174
         // 005184c4: sub eax, 0x1
         // 005184c7: jz 0x5184d6
      [-]8be55dc3
         // 00423e12: mov esp, ebp
         // 00423e14: pop ebp
         // 00423e15: retn 
      [-]558bec568b7508578b7d0c0fb70683e802
         // 005afc80: push ebp
         // 005afc81: mov ebp, esp
         // 005afc83: push esi
         // 005afc84: mov esi, ss:[ebp+0x8]
         // 005afc87: push edi
         // 005afc88: mov edi, ss:[ebp+0xc]
         // 005afc8b: movzx eax, b2 ds:[esi]
         // 005afc8e: sub eax, 0x2
      [-]6a2e578d4604506a02e8
         // 00422a13: push 0x2e
         // 00422a15: push edi
         // 00422a16: lea eax, ds:[esi+0x4]
         // 00422a19: push eax
         // 00422a1a: push 0x2
         // 00422a1c: call 0x427950
      [-]000083c41085c074
         // 00422a21: add esp, 0x10
         // 00422a24: test eax, eax
         // 00422a26: jz 0x422a44
      [-]0fb7460250ff15
         // 00547488: movzx eax, b2 ds:[esi+0x2]
         // 0054748c: push eax
         // 0054748d: call ds:[ntohs]
      [-]000fb7c88b45105f5e8908
         // 00547493: movzx ecx, b2 ax
         // 00547496: mov eax, ss:[ebp+0x10]
         // 00547499: pop edi
         // 0054749a: pop esi
         // 0054749b: mov ds:[eax], ecx
      [-]8b4510c607005f5ec700????
         // 005afcc1: mov eax, ss:[ebp+0x10]
         // 005afcc4: mov b1 ds:[edi], b1 0x0
         // 005afcc7: pop edi
         // 005afcc8: pop esi
         // 005afcc9: mov ds:[eax], 0x0
      [-]558bec83ec086a006a00c745fc????????c745f8????????ff15
         // 00547930: push ebp
         // 00547931: mov ebp, esp
         // 00547933: sub esp, 0x8
         // 00547936: push 0x0
         // 00547938: push 0x0
         // 0054793a: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00547941: mov ss:[ebp+0xfffffffffffffff8], 0x4
         // 00547948: call ds:[SleepEx]
      [-]008d45f8508d45fc5068????????68????????ff7508ff15
         // 0054794e: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00547951: push eax
         // 00547952: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00547955: push eax
         // 00547956: push 0x1007
         // 0054795b: push 0xffff
         // 00547960: push ss:[ebp+0x8]
         // 00547963: call ds:[getsockopt]
      [-]0085c07408
         // 00547969: test eax, eax
         // 0054796b: jz 0x547975
      [-]85c0740b
         // 00518fc8: test eax, eax
         // 00518fca: jz 0x518fd7
      [-]3d????????7404
         // 00518fcc: cmp eax, 0x2748
         // 00518fd1: jz 0x518fd7
      [-]8b550c85d27402
         // 00518fdc: mov edx, ss:[ebp+0xc]
         // 00518fdf: test edx, edx
         // 00518fe1: jz 0x518fe5
      [-]c18be55dc3
         // 00518fe5: mov eax, ecx
         // 00518fe7: mov esp, ebp
         // 00518fe9: pop ebp
         // 00518fea: retn 
      [-]558bec8d450850e8
         // 005bb9e0: push ebp
         // 005bb9e1: mov ebp, esp
         // 005bb9e3: lea eax, ss:[ebp+0x8]
         // 005bb9e6: push eax
         // 005bb9e7: call 0x594187
      [-]83c40485c0741b
         // 005bb9ec: add esp, 0x4
         // 005bb9ef: test eax, eax
         // 005bb9f1: jz 0x5bba0e
      [-]0f10008b4d100f11010f1040100f1141108b402089412033c05dc3
         // 0051a4b3: movups b16 xmm0, b16 ds:[eax]
         // 0051a4b6: mov ecx, ss:[ebp+0x10]
         // 0051a4b9: movups b16 ds:[ecx], b16 xmm0
         // 0051a4bc: movups b16 xmm0, b16 ds:[eax+0x10]
         // 0051a4c0: movups b16 ds:[ecx+0x10], b16 xmm0
         // 0051a4c4: mov eax, ds:[eax+0x20]
         // 0051a4c7: mov ds:[ecx+0x20], eax
         // 0051a4ca: xor eax, eax
         // 0051a4cc: pop ebp
         // 0051a4cd: retn 
      [-]b8????????5dc3
         // 0051a4ce: mov eax, 0x2b
         // 0051a4d3: pop ebp
         // 0051a4d4: retn 
      [-]558bec51538b5d08b8
         // 00422000: push ebp
         // 00422001: mov ebp, esp
         // 00422003: push ecx
         // 00422004: push ebx
         // 00422005: mov ebx, ss:[ebp+0x8]
         // 00422008: mov eax, 0x45b75c
      [-]565733f6
         // 0042200d: push esi
         // 0042200e: push edi
         // 0042200f: xor esi, esi
      [-]837d0c03bf
         // 00422018: cmp ss:[ebp+0xc], 0x3
         // 0042201c: mov edi, 0x45b710
      [-]ff3753e8
         // 00423134: push ds:[edi]
         // 00423136: push ebx
         // 00423137: call 0x424e50
      [-]83c40885c0751a
         // 0042313c: add esp, 0x8
         // 0042313f: test eax, eax
         // 00423141: jnz 0x42315d
      [-]4683c70483fe077ce8
         // 0051a513: inc esi
         // 0051a514: add edi, 0x4
         // 0051a517: cmp esi, 0x7
         // 0051a51a: jl 0x51a504
      [-]005f0f45c65e5b8be55dc3
         // 0051a523: pop edi
         // 0051a524: cmovnz eax, esi
         // 0051a527: pop esi
         // 0051a528: pop ebx
         // 0051a529: mov esp, ebp
         // 0051a52b: pop ebp
         // 0051a52c: retn 
      [-]005f0f45c65e5b8be55dc3
         // 0051a53b: pop edi
         // 0051a53c: cmovnz eax, esi
         // 0051a53f: pop esi
         // 0051a540: pop ebx
         // 0051a541: mov esp, ebp
         // 0051a543: pop ebp
         // 0051a544: retn 
      [-]558bec51538b5d085657
         // 00423180: push ebp
         // 00423181: mov ebp, esp
         // 00423183: push ecx
         // 00423184: push ebx
         // 00423185: mov ebx, ss:[ebp+0x8]
         // 00423188: push esi
         // 00423189: push edi
      [-]ff3753e8
         // 00423198: push ds:[edi]
         // 0042319a: push ebx
         // 0042319b: call 0x424e50
      [-]83c40885c0751a
         // 004231a0: add esp, 0x8
         // 004231a3: test eax, eax
         // 004231a5: jnz 0x4231c1
      [-]4683c70483fe0c7ce8
         // 0051a577: inc esi
         // 0051a578: add edi, 0x4
         // 0051a57b: cmp esi, 0xc
         // 0051a57e: jl 0x51a568
      [-]005f0f45c65e5b8be55dc3
         // 0051a587: pop edi
         // 0051a588: cmovnz eax, esi
         // 0051a58b: pop esi
         // 0051a58c: pop ebx
         // 0051a58d: mov esp, ebp
         // 0051a58f: pop ebp
         // 0051a590: retn 
      [-]005f0f45c65e5b8be55dc3
         // 0051a59f: pop edi
         // 0051a5a0: cmovnz eax, esi
         // 0051a5a3: pop esi
         // 0051a5a4: pop ebx
         // 0051a5a5: mov esp, ebp
         // 0051a5a7: pop ebp
         // 0051a5a8: retn 
      [-]558bec538b5d085657be
         // 004220d0: push ebp
         // 004220d1: mov ebp, esp
         // 004220d3: push ebx
         // 004220d4: mov ebx, ss:[ebp+0x8]
         // 004220d7: push esi
         // 004220d8: push edi
         // 004220d9: mov esi, 0x45b778
      [-]83c40885c07511
         // 004231f7: add esp, 0x8
         // 004231fa: test eax, eax
         // 004231fc: jnz 0x42320f
      [-]4783c60c83ff
         // 0051a5ce: inc edi
         // 0051a5cf: add esi, 0xc
         // 0051a5d2: cmp edi, 0x44
      [-]5f5e83c8ff5b5dc3
         // 0051a5d7: pop edi
         // 0051a5d8: pop esi
         // 0051a5d9: or eax, 0xffffffffffffffff
         // 0051a5dc: pop ebx
         // 0051a5dd: pop ebp
         // 0051a5de: retn 
      [-]8b4608c1e0042b46085f5ec1e0025b5dc3
         // 0051a5df: mov eax, ds:[esi+0x8]
         // 0051a5e2: shl eax, b1 0x4
         // 0051a5e5: sub eax, ds:[esi+0x8]
         // 0051a5e8: pop edi
         // 0051a5e9: pop esi
         // 0051a5ea: shl eax, b1 0x2
         // 0051a5ed: pop ebx
         // 0051a5ee: pop ebp
         // 0051a5ef: retn 
      [-]558bec83ec088d45f850ff7508e8
         // 00424c10: push ebp
         // 00424c11: mov ebp, esp
         // 00424c13: sub esp, 0x8
         // 00424c16: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00424c19: push eax
         // 00424c1a: push ss:[ebp+0x8]
         // 00424c1d: call 0x424d70
      [-]01000083c408
         // 00424c22: add esp, 0x8
      [-]83c8ff0bd08be55dc3
         // 0051a614: or eax, 0xffffffffffffffff
         // 0051a617: or edx, eax
         // 0051a619: mov esp, ebp
         // 0051a61b: pop ebp
         // 0051a61c: retn 
      [-]558bec83ec
         // 00423380: push ebp
         // 00423381: mov ebp, esp
         // 00423383: sub esp, 0x60
      [-]0033c58945fc8b
         // 0042338b: xor eax, ebp
         // 0042338d: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00423390: mov eax, ss:[ebp+0x8]
      [-]c745????????ff89
         // 004233c1: mov ss:[ebp+0xffffffffffffffa8], 0xffffffffffffffff
         // 004233c8: mov ss:[ebp+0xffffffffffffffc4], ecx
      [-]00008b7d
         // 00424de7: mov edi, ss:[ebp+0xffffffffffffffc8]
      [-]0fb60750e8
         // 00424dea: movzx eax, b1 ds:[edi]
         // 00424ded: push eax
         // 00424dee: call _isalpha
      [-]83c40885c00f84
         // 00424df3: add esp, 0x8
         // 00424df6: test eax, eax
         // 00424df8: jz 0x424ec8
      [-]8a064684c075f9
         // 0051a817: mov b1 al, b1 ds:[esi]
         // 0051a819: inc esi
         // 0051a81a: test b1 al, b1 al
         // 0051a81c: jnz 0x51a817
      [-]8d45dc5650e8
         // 004d1523: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 004d1526: push esi
         // 004d1527: push eax
         // 004d1528: call 0x4d11a0
      [-]fcffff83c4088945a883f8ff753a
         // 004d152d: add esp, 0x8
         // 004d1530: mov ss:[ebp+0xffffffffffffffa8], eax
         // 004d1533: cmp eax, 0xffffffffffffffff
         // 004d1536: jnz 0x4d1572
      [-]8d45dc50e8
         // 004d153e: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 004d1541: push eax
         // 004d1542: call 0x4d1200
      [-]ffff83c4048945
         // 004d1547: add esp, 0x4
         // 004d154a: mov ss:[ebp+0xffffffffffffffc0], eax
      [-]83f8ff7520
         // 004d154d: cmp eax, 0xffffffffffffffff
         // 004d1550: jnz 0x4d1572
      [-]83fbff0f85
         // 004d1552: cmp ebx, 0xffffffffffffffff
         // 004d1555: jnz 0x4d18b6
      [-]8d45dc50e8
         // 005bbdab: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 005bbdae: push eax
         // 005bbdaf: call 0x5bbae0
      [-]ffff8bd883c40483fbff0f84
         // 005bbdb4: mov ebx, eax
         // 005bbdb6: add esp, 0x4
         // 005bbdb9: cmp ebx, 0xffffffffffffffff
         // 005bbdbc: jz 0x5bc121
      [-]03fe8b75
         // 00422395: add edi, esi
         // 00422397: mov esi, ss:[ebp+0xffffffffffffffb4]
      [-]0fb60750e8
         // 0051a8a8: movzx eax, b1 ds:[edi]
         // 0051a8ab: push eax
         // 0051a8ac: call _isdigit
      [-]83c40485c0
         // 0051a8b1: add esp, 0x4
         // 0051a8b4: test eax, eax
      [-]8bca2bcf83f90475
         // 0051a937: mov ecx, edx
         // 0051a939: sub ecx, edi
         // 0051a93b: cmp ecx, 0x4
         // 0051a93e: jnz 0x51a992
      [-]81fe????????7f
         // 0051a940: cmp esi, 0x578
         // 0051a946: jg 0x51a992
      [-]8a47ff8845
         // 0051a94d: mov b1 al, b1 ds:[edi+0xffffffffffffffff]
         // 0051a950: mov b1 ss:[ebp+0xffffffffffffffcf], b1 al
      [-]3c2b7404
         // 0051a953: cmp b1 al, b1 0x2b
         // 0051a955: jz 0x51a95b
      [-]b8????????
         // 0051a95b: mov eax, 0x51eb851f
      [-]f7ee8bcec1fa058bc2c1e81f03c28b55
         // 0051a967: imul esi
         // 0051a969: mov ecx, esi
         // 0051a96b: sar edx, b1 0x5
         // 0051a96e: mov eax, edx
         // 0051a970: shr eax, b1 0x1f
         // 0051a973: add eax, edx
         // 0051a975: mov edx, ss:[ebp+0xffffffffffffffc0]
      [-]8d0480c1e0032bc88bd9c1e3042bd9c1e302807d
         // 0051a978: lea eax, ds:[eax+eax*0x4]
         // 0051a97b: shl eax, b1 0x3
         // 0051a97e: sub ecx, eax
         // 0051a980: mov ebx, ecx
         // 0051a982: shl ebx, b1 0x4
         // 0051a985: sub ebx, ecx
         // 0051a987: shl ebx, b1 0x2
         // 0051a98a: cmp b1 ss:[ebp+0xffffffffffffffcf], b1 0x2b
      [-]83f80875
         // 004224bc: cmp eax, 0x8
         // 004224bf: jnz 0x42252b
      [-]83f9ff75
         // 0051a9a1: cmp ecx, 0xffffffffffffffff
         // 0051a9a4: jnz 0x51aa0b
      [-]8d46ff83f81e77
         // 0051aa22: lea eax, ds:[esi+0xffffffffffffffff]
         // 0051aa25: cmp eax, 0x1e
         // 0051aa28: ja 0x51aa34
      [-]83f8ff0f84
         // 005bc022: cmp eax, 0xffffffffffffffff
         // 005bc025: jz 0x5bc121
      [-]8945f88d45e489
         // 0051ab1b: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0051ab1e: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 0051ab21: mov ss:[ebp+0xffffffffffffffe4], edx
      [-]faffff8b
         // 0051ab39: mov ecx, eax
      [-]33c05b8b4dfc33cde8
         // 00516273: xor eax, eax
         // 00516275: pop ebx
         // 00516276: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00516279: xor ecx, ebp
         // 0051627b: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 00516280: mov esp, ebp
         // 00516282: pop ebp
         // 00516283: retn 
      [-]8b4dfc83c8ff5f5e33cd5be8
         // 004226a4: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004226a7: or eax, 0xffffffffffffffff
         // 004226aa: pop edi
         // 004226ab: pop esi
         // 004226ac: xor ecx, ebp
         // 004226ae: pop ebx
         // 004226af: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 004226b4: mov esp, ebp
         // 004226b6: pop ebp
         // 004226b7: retn 
      [-]558bec568b75088b06803800741d
         // 0051aba0: push ebp
         // 0051aba1: mov ebp, esp
         // 0051aba3: push esi
         // 0051aba4: mov esi, ss:[ebp+0x8]
         // 0051aba7: mov eax, ds:[esi]
         // 0051aba9: cmp b1 ds:[eax], b1 0x0
         // 0051abac: jz 0x51abcb
      [-]8b060fb60050e8
         // 005bc150: mov eax, ds:[esi]
         // 005bc152: movzx eax, b1 ds:[eax]
         // 005bc155: push eax
         // 005bc156: call _isalnum
      [-]83c40485c07509
         // 005bc15b: add esp, 0x4
         // 005bc15e: test eax, eax
         // 005bc160: jnz 0x5bc16b
      [-]ff068b0680380075e5
         // 0051abc2: inc ds:[esi]
         // 0051abc4: mov eax, ds:[esi]
         // 0051abc6: cmp b1 ds:[eax], b1 0x0
         // 0051abc9: jnz 0x51abb0
      [-]558bec53568b7510578b7d0885ff7502
         // 0051abd0: push ebp
         // 0051abd1: mov ebp, esp
         // 0051abd3: push ebx
         // 0051abd4: push esi
         // 0051abd5: mov esi, ss:[ebp+0x10]
         // 0051abd8: push edi
         // 0051abd9: mov edi, ss:[ebp+0x8]
         // 0051abdc: test edi, edi
         // 0051abde: jnz 0x51abe2
      [-]8a0784c07421
         // 0051abe2: mov b1 al, b1 ds:[edi]
         // 0051abe4: test b1 al, b1 al
         // 0051abe6: jz 0x51ac09
      [-]8b5d0c0f1f440000
         // 0051abe8: mov ebx, ss:[ebp+0xc]
         // 0051abeb: nop ds:[eax+eax+0x0]
      [-]0fbec05053e8
         // 004d1920: movsx eax, b1 al
         // 004d1923: push eax
         // 004d1924: push ebx
         // 004d1925: call _strchr
      [-]83c40885c0740f
         // 004d192a: add esp, 0x8
         // 004d192d: test eax, eax
         // 004d192f: jz 0x4d1940
      [-]8a47014784c075e7
         // 0051ac01: mov b1 al, b1 ds:[edi+0x1]
         // 0051ac04: inc edi
         // 0051ac05: test b1 al, b1 al
         // 0051ac07: jnz 0x51abf0
      [-]5f5e33c05b5dc3
         // 0051ac09: pop edi
         // 0051ac0a: pop esi
         // 0051ac0b: xor eax, eax
         // 0051ac0d: pop ebx
         // 0051ac0e: pop ebp
         // 0051ac0f: retn 
      [-]803f0074f4
         // 0051ac10: cmp b1 ds:[edi], b1 0x0
         // 0051ac13: jz 0x51ac09
      [-]8d47018906803800741d
         // 0051ac15: lea eax, ds:[edi+0x1]
         // 0051ac18: mov ds:[esi], eax
         // 0051ac1a: cmp b1 ds:[eax], b1 0x0
         // 0051ac1d: jz 0x51ac3c
      [-]8b060fbe005053e8
         // 005bc1c0: mov eax, ds:[esi]
         // 005bc1c2: movsx eax, b1 ds:[eax]
         // 005bc1c5: push eax
         // 005bc1c6: push ebx
         // 005bc1c7: call _strchr
      [-]83c40885c07509
         // 005bc1cc: add esp, 0x8
         // 005bc1cf: test eax, eax
         // 005bc1d1: jnz 0x5bc1dc
      [-]ff068b0680380075e4
         // 0051ac33: inc ds:[esi]
         // 0051ac35: mov eax, ds:[esi]
         // 0051ac37: cmp b1 ds:[eax], b1 0x0
         // 0051ac3a: jnz 0x51ac20
      [-]8b068038007405
         // 0051ac3c: mov eax, ds:[esi]
         // 0051ac3e: cmp b1 ds:[eax], b1 0x0
         // 0051ac41: jz 0x51ac48
      [-]c60000ff06
         // 0051ac43: mov b1 ds:[eax], b1 0x0
         // 0051ac46: inc ds:[esi]
      [-]8bc75f5e5b5dc3
         // 0051ac48: mov eax, edi
         // 0051ac4a: pop edi
         // 0051ac4b: pop esi
         // 0051ac4c: pop ebx
         // 0051ac4d: pop ebp
         // 0051ac4e: retn 
      [-]558bec83ec088b4d085356570fbe018d5df833ffc645f80033f68945fc85c00f8486000000
         // 0051c250: push ebp
         // 0051c251: mov ebp, esp
         // 0051c253: sub esp, 0x8
         // 0051c256: mov ecx, ss:[ebp+0x8]
         // 0051c259: push ebx
         // 0051c25a: push esi
         // 0051c25b: push edi
         // 0051c25c: movsx eax, b1 ds:[ecx]
         // 0051c25f: lea ebx, ss:[ebp+0xfffffffffffffff8]
         // 0051c262: xor edi, edi
         // 0051c264: mov b1 ss:[ebp+0xfffffffffffffff8], b1 0x0
         // 0051c268: xor esi, esi
         // 0051c26a: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0051c26d: test eax, eax
         // 0051c26f: jz 0x51c2fb
      [-]894d08e8
         // 0042671c: mov ss:[ebp+0x8], ecx
         // 0042671f: call _strchr
      [-]83c40885c07435
         // 00426724: add esp, 0x8
         // 00426727: test eax, eax
         // 00426729: jz 0x426760
      [-]8a130fb6ca8d0c8903c981e9
         // 0042672b: mov b1 dl, b1 ds:[ebx]
         // 0042672d: movzx ecx, b1 dl
         // 00426730: lea ecx, ds:[ecx+ecx*0x4]
         // 00426733: add ecx, ecx
         // 00426735: sub ecx, 0x45cc48
      [-]03c885ff7404
         // 0042673b: add ecx, eax
         // 0042673d: test edi, edi
         // 0042673f: jz 0x426745
      [-]84d27456
         // 0051c2a1: test b1 dl, b1 dl
         // 0051c2a3: jz 0x51c2fb
      [-]81f9????????774e
         // 0051c2a5: cmp ecx, 0xff
         // 0051c2ab: ja 0x51c2fb
      [-]880b85ff7522
         // 0051c2ad: mov b1 ds:[ebx], b1 cl
         // 0051c2af: test edi, edi
         // 0051c2b1: jnz 0x51c2d5
      [-]4683fe047f42
         // 0051c2b3: inc esi
         // 0051c2b4: cmp esi, 0x4
         // 0051c2b7: jg 0x51c2fb
      [-]bf????????eb15
         // 0051c2b9: mov edi, 0x1
         // 0051c2be: jmp 0x51c2d5
      [-]837dfc2e7535
         // 0051c2c0: cmp ss:[ebp+0xfffffffffffffffc], 0x2e
         // 0051c2c4: jnz 0x51c2fb
      [-]85ff7431
         // 0051c2c6: test edi, edi
         // 0051c2c8: jz 0x51c2fb
      [-]83fe04742c
         // 0051c2ca: cmp esi, 0x4
         // 0051c2cd: jz 0x51c2fb
      [-]4333ffc60300
         // 0051c2cf: inc ebx
         // 0051c2d0: xor edi, edi
         // 0051c2d2: mov b1 ds:[ebx], b1 0x0
      [-]8b4d080fbe018945fc85c07593
         // 0051c2d5: mov ecx, ss:[ebp+0x8]
         // 0051c2d8: movsx eax, b1 ds:[ecx]
         // 0051c2db: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0051c2de: test eax, eax
         // 0051c2e0: jnz 0x51c275
      [-]83fe047c14
         // 0051c2e2: cmp esi, 0x4
         // 0051c2e5: jl 0x51c2fb
      [-]8b4d0c8b45f85f5e8901b8????????5b8be55dc3
         // 0051c2e7: mov ecx, ss:[ebp+0xc]
         // 0051c2ea: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0051c2ed: pop edi
         // 0051c2ee: pop esi
         // 0051c2ef: mov ds:[ecx], eax
         // 0051c2f1: mov eax, 0x1
         // 0051c2f6: pop ebx
         // 0051c2f7: mov esp, ebp
         // 0051c2f9: pop ebp
         // 0051c2fa: retn 
      [-]5f5e33c05b8be55dc3
         // 0051c2fb: pop edi
         // 0051c2fc: pop esi
         // 0051c2fd: xor eax, eax
         // 0051c2ff: pop ebx
         // 0051c300: mov esp, ebp
         // 0051c302: pop ebp
         // 0051c303: retn 
      [-]558bec6a006a00ff750cff75086a006a00e8
         // 0051c310: push ebp
         // 0051c311: mov ebp, esp
         // 0051c313: push 0x0
         // 0051c315: push 0x0
         // 0051c317: push ss:[ebp+0xc]
         // 0051c31a: push ss:[ebp+0x8]
         // 0051c31d: push 0x0
         // 0051c31f: push 0x0
         // 0051c321: call __beginthreadex
      [-]c41885c07405
         // 0051c329: test eax, eax
         // 0051c32b: jz 0x51c332
      [-]83f8ff7502
         // 0051c32d: cmp eax, 0xffffffffffffffff
         // 0051c330: jnz 0x51c334
      [-]558bec83
         // 0051c3a0: push ebp
         // 0051c3a1: mov ebp, esp
         // 0051c3a3: sub ss:[ebp+0x8], 0x2
      [-]558bec83ec14a1
         // 00427980: push ebp
         // 00427981: mov ebp, esp
         // 00427983: sub esp, 0x14
         // 00427986: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b4d08578b7d0cc645ec000fb64103500fb64102500fb64101500fb6015068
         // 0042798b: xor eax, ebp
         // 0042798d: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00427990: mov ecx, ss:[ebp+0x8]
         // 00427993: push edi
         // 00427994: mov edi, ss:[ebp+0xc]
         // 00427997: mov b1 ss:[ebp+0xffffffffffffffec], b1 0x0
         // 0042799b: movzx eax, b1 ds:[ecx+0x3]
         // 0042799f: push eax
         // 004279a0: movzx eax, b1 ds:[ecx+0x2]
         // 004279a4: push eax
         // 004279a5: movzx eax, b1 ds:[ecx+0x1]
         // 004279a9: push eax
         // 004279aa: movzx eax, b1 ds:[ecx]
         // 004279ad: push eax
         // 004279ae: push 0x45dc44
      [-]8d45ec6a1050e8
         // 004279b3: lea eax, ss:[ebp+0xffffffffffffffec]
         // 004279b6: push 0x10
         // 004279b8: push eax
         // 004279b9: call _snprintf
      [-]8d4dec83c41c8d5101
         // 004279be: lea ecx, ss:[ebp+0xffffffffffffffec]
         // 004279c1: add esp, 0x1c
         // 004279c4: lea edx, ds:[ecx+0x1]
      [-]8a014184c075f9
         // 0051c417: mov b1 al, b1 ds:[ecx]
         // 0051c419: inc ecx
         // 0051c41a: test b1 al, b1 al
         // 0051c41c: jnz 0x51c417
      [-]2bca742e
         // 0051c41e: sub ecx, edx
         // 0051c420: jz 0x51c450
      [-]3b4d107329
         // 0051c422: cmp ecx, ss:[ebp+0x10]
         // 0051c425: jnb 0x51c450
      [-]568d4dec8bf78bc12bf0
         // 0051c427: push esi
         // 0051c428: lea ecx, ss:[ebp+0xffffffffffffffec]
         // 0051c42b: mov esi, edi
         // 0051c42d: mov eax, ecx
         // 0051c42f: sub esi, eax
      [-]8a118d490188540eff84d275f3
         // 0051c431: mov b1 dl, b1 ds:[ecx]
         // 0051c433: lea ecx, ds:[ecx+0x1]
         // 0051c436: mov b1 ds:[esi+ecx+0xffffffffffffffff], b1 dl
         // 0051c43a: test b1 dl, b1 dl
         // 0051c43c: jnz 0x51c431
      [-]5e8bc75f8b4dfc33cde8
         // 004268de: pop esi
         // 004268df: mov eax, edi
         // 004268e1: pop edi
         // 004268e2: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004268e5: xor ecx, ebp
         // 004268e7: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 004268ec: mov esp, ebp
         // 004268ee: pop ebp
         // 004268ef: retn 
      [-]008b4dfc33
         // 0051c452: call ds:[SetLastError]
         // 0051c458: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0051c45d: xor ecx, ebp
      [-]ff8be55dc3
         // 0051c465: mov esp, ebp
         // 0051c467: pop ebp
         // 0051c468: retn 
      [-]558bec568b7508578b7d0c56
         // 004d9150: push ebp
         // 004d9151: mov ebp, esp
         // 004d9153: push esi
         // 004d9154: mov esi, ss:[ebp+0x8]
         // 004d9157: push edi
         // 004d9158: mov edi, ss:[ebp+0xc]
         // 004d915b: push esi
      [-]85c07517
         // 004d9167: test eax, eax
         // 004d9169: jnz 0x4d9182
      [-]000083c40485c0750a
         // 0054c44a: add esp, 0x4
         // 0054c44d: test eax, eax
         // 0054c44f: jnz 0x54c45b
      [-]000083c408
         // 0054c458: add esp, 0x8
      [-]5f5e5dc3
         // 0051c4ab: pop edi
         // 0051c4ac: pop esi
         // 0051c4ad: pop ebp
         // 0051c4ae: retn 
      [-]558bec5156578b7d086a006a00
         // 00428020: push ebp
         // 00428021: mov ebp, esp
         // 00428023: push ecx
         // 00428024: push esi
         // 00428025: push edi
         // 00428026: mov edi, ss:[ebp+0x8]
         // 00428029: push 0x0
         // 0042802b: push 0x0
      [-]8b3756c7
         // 00428034: mov esi, ds:[edi]
         // 00428036: push esi
         // 00428037: mov ds:[esi+0x18], 0xffffffffffffffff
      [-]6a006a0056e8
         // 0042804a: push 0x0
         // 0042804c: push 0x0
         // 0042804e: push esi
         // 0042804f: call 0x42db70
      [-]8b750c8d45fc565057e8
         // 00428068: mov esi, ss:[ebp+0xc]
         // 0042806b: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0042806e: push esi
         // 0042806f: push eax
         // 00428070: push edi
         // 00428071: call 0x427f30
      [-]ffff83c43c85c075
         // 00428076: add esp, 0x3c
         // 00428079: test eax, eax
         // 0042807b: jnz 0x428093
      [-]ff75fc57e8
         // 005bde0e: push ss:[ebp+0xfffffffffffffffc]
         // 005bde11: push edi
         // 005bde12: call 0x5bcd60
      [-]5f5e8be55dc3
         // 0051cae3: pop edi
         // 0051cae4: pop esi
         // 0051cae5: mov esp, ebp
         // 0051cae7: pop ebp
         // 0051cae8: retn 
      [-]558bec8b
         // 00427180: push ebp
         // 00427181: mov ebp, esp
         // 00427183: mov ecx, ss:[ebp+0xc]
      [-]ff83c40cb8????????
         // 0042719e: call 0x4209d0
         // 004271a3: add esp, 0xc
         // 004271a6: mov eax, 0x43
      [-]85c00f45c88d86
         // 00518436: test eax, eax
         // 00518438: cmovnz ecx, eax
         // 0051843b: lea eax, ds:[esi+0x3d0]
      [-]010083c40c85
         // 0051844d: add esp, 0xc
         // 00518450: test eax, eax
      [-]558bec8b4d0c8d81????????83f864721a
         // 0051e280: push ebp
         // 0051e281: mov ebp, esp
         // 0051e283: mov ecx, ss:[ebp+0xc]
         // 0051e286: lea eax, ds:[ecx+0xffffffffffffff38]
         // 0051e28c: cmp eax, 0x64
         // 0051e28f: jb 0x51e2ab
      [-]8b45085168
         // 004298a1: mov eax, ss:[ebp+0x8]
         // 004298a4: push ecx
         // 004298a5: push 0x45deb8
      [-]ff83c40cb8
         // 004298b1: add esp, 0xc
         // 004298b4: mov eax, 0x43
      [-]6a00ff7508e8
         // 004dd30b: push 0x0
         // 004dd30d: push ss:[ebp+0x8]
         // 004dd310: call 0x4db0d0
      [-]83c40833c05dc3
         // 004dd315: add esp, 0x8
         // 004dd318: xor eax, eax
         // 004dd31a: pop ebp
         // 004dd31b: retn 
      [-]558bec33c0ba????????817d0c????????50ff75080f44d0e8
         // 004dd360: push ebp
         // 004dd361: mov ebp, esp
         // 004dd363: xor eax, eax
         // 004dd365: mov edx, 0x38
         // 004dd36a: cmp ss:[ebp+0xc], 0xfa
         // 004dd371: push eax
         // 004dd372: push ss:[ebp+0x8]
         // 004dd375: cmovz edx, eax
         // 004dd378: call 0x4db0d0
      [-]83c4088bc25dc3
         // 004dd37d: add esp, 0x8
         // 004dd380: mov eax, edx
         // 004dd382: pop ebp
         // 004dd383: retn 
      [-]0033c58945fc8b450c53
         // 00430c4b: xor eax, ebp
         // 00430c4d: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00430c50: mov eax, ss:[ebp+0xc]
         // 00430c53: push ebx
      [-]000083c40485c00f85
         // 00430c80: add esp, 0x4
         // 00430c83: test eax, eax
         // 00430c85: jnz 0x4310ec
      [-]04000083c40485c00f85
         // 004e3be7: add esp, 0x4
         // 004e3bea: test eax, eax
         // 004e3bec: jnz 0x4e403b
      [-]5e5b8b4dfc33cde8
         // 005c1158: pop esi
         // 005c115a: pop ebx
         // 005c115b: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 005c115e: xor ecx, ebp
         // 005c1160: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 005c1165: mov esp, ebp
         // 005c1167: pop ebp
         // 005c1168: retn 
      [-]85c0750e
         // 0042f351: test eax, eax
         // 0042f353: jnz 0x42f363
      [-]85c0750e
         // 0042f374: test eax, eax
         // 0042f376: jnz 0x42f386
      [-]83f8ff75
         // 004e3d19: cmp eax, 0xffffffffffffffff
         // 004e3d1c: jnz 0x4e3d41
      [-]5b8b4dfc33cde8
         // 00430de9: pop ebx
         // 00430dea: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00430ded: xor ecx, ebp
         // 00430def: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 00430df4: mov esp, ebp
         // 00430df6: pop ebp
         // 00430df7: retn 
      [-]6af6ff15
         // 00553d78: push 0xfffffffffffffff6
         // 00553d7a: call ds:[GetStdHandle]
      [-]0083f80374
         // 00553d93: cmp eax, 0x3
         // 00553d96: jz 0x553db0
      [-]ba????????eb0a
         // 00523df9: mov edx, 0x3e8
         // 00523dfe: jmp 0x523e0a
      [-]ba????????
         // 00523e05: mov edx, 0x64
      [-]0083e8000f84
         // 005c12ae: sub eax, 0x0
         // 005c12b1: jz 0x5c13d3
      [-]83e8010f84
         // 004e3da6: sub eax, 0x1
         // 004e3da9: jz 0x4e3e64
      [-]2d????????0f85
         // 004e3daf: sub eax, 0x101
         // 004e3db4: jnz 0x4e3f75
      [-]0f1f440000
         // 00523e3b: nop ds:[eax+eax+0x0]
      [-]6a008d45
         // 00553e36: push 0x0
         // 00553e38: lea eax, ss:[ebp+0xffffffffffffffc0]
      [-]506a006a006a00ff75
         // 00553e3b: push eax
         // 00553e3c: push 0x0
         // 00553e3e: push 0x0
         // 00553e40: push 0x0
         // 00553e42: push ss:[ebp+0xffffffffffffffb0]
      [-]0085c074
         // 00553e4b: test eax, eax
         // 00553e4d: jz 0x553eaf
      [-]6a008d45
         // 00553e59: push 0x0
         // 00553e5b: lea eax, ss:[ebp+0xffffffffffffffc0]
      [-]0085c074
         // 00553e6e: test eax, eax
         // 00553e70: jz 0x553eaf
      [-]00008bf083c40c85f60f84
         // 005c1374: mov esi, eax
         // 005c1376: add esp, 0xc
         // 005c1379: test esi, esi
         // 005c137b: jz 0x5c12d0
      [-]0085c075
         // 005c13a3: test eax, eax
         // 005c13a5: jnz 0x5c13b3
      [-]be????????e9
         // 005c13a9: mov esi, 0x1a
         // 005c13ae: jmp 0x5c14a5
      [-]00008bf083c40c85f60f84
         // 004e3e96: mov esi, eax
         // 004e3e98: add esp, 0xc
         // 004e3e9b: test esi, esi
         // 004e3e9d: jz 0x4e3f75
      [-]8d45d050ff75
         // 004e3eaa: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 004e3eb4: push eax
         // 004e3eb5: push ss:[ebp+0xffffffffffffffb8]
      [-]83f8ff75
         // 004e3ebe: cmp eax, 0xffffffffffffffff
         // 004e3ec1: jnz 0x4e3eef
      [-]003d????????0f84
         // 0042f57b: cmp eax, 0x2734
         // 0042f580: jz 0x42f635
      [-]ff83c40c
         // 0051f694: add esp, 0xc
      [-]f645d00174
         // 004e3eef: test b1 ss:[ebp+0xffffffffffffffd0], b1 0x1
         // 004e3ef3: jz 0x4e3f66
      [-]ff8bf083c41483fe5174
         // 00523f8c: call 0x50c310
         // 00523f91: mov esi, eax
         // 00523f93: add esp, 0x14
         // 00523f96: cmp esi, 0x51
         // 00523f99: jz 0x524005
      [-]00008bf083c40c85f674
         // 005c1466: mov esi, eax
         // 005c1468: add esp, 0xc
         // 005c146b: test esi, esi
         // 005c146d: jz 0x5c1473
      [-]83380074
         // 004e3f46: cmp ds:[eax], 0x0
         // 004e3f49: jz 0x4e3f66
      [-]8378040075
         // 00523fda: cmp ds:[eax+0x4], 0x0
         // 00523fde: jnz 0x523ff3
      [-]00008b45
         // 004e3f59: mov eax, ss:[ebp+0xffffffffffffffa4]
      [-]83c404c74004????????
         // 004e3f5c: add esp, 0x4
         // 004e3f5f: mov ds:[eax+0x4], 0x1
      [-]f645d020
         // 0042e513: test b1 ss:[ebp+0xffffffffffffffd0], b1 0x20
      [-]85c07515
         // 004e3feb: test eax, eax
         // 004e3fed: jnz 0x4e4004
      [-]ff83c40c
         // 0042f6ae: add esp, 0xc
      [-]0085c07515
         // 0042f6ba: test eax, eax
         // 0042f6bc: jnz 0x42f6d3
      [-]ff83c40c
         // 0042f6d0: add esp, 0xc
      [-]ff6a006a
         // 004310d5: push 0xffffffffffffffff
         // 004310d7: push 0x0
         // 004310d9: push 0x0
      [-]6aff6aff
         // 004310db: push 0xffffffffffffffff
         // 004310dd: push 0xffffffffffffffff
      [-]8b4dfc5f
         // 0042f6ec: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042f6ef: pop edi
      [-]33cd5be8
         // 0042f6f1: xor ecx, ebp
         // 0042f6f3: pop ebx
         // 0042f6f4: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 0042f6f9: mov esp, ebp
         // 0042f6fb: pop ebp
         // 0042f6fc: retn 
      [-]558bec81ec????????a1
         // 00431150: push ebp
         // 00431151: mov ebp, esp
         // 00431153: sub esp, 0x188
         // 00431159: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b
         // 0043115e: xor eax, ebp
         // 00431160: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00431163: mov eax, ss:[ebp+0x8]
      [-]8d85????????68
         // 0042f787: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 0042f78d: push 0x45ede8
      [-]68????????50e8
         // 0042f792: push 0x100
         // 0042f797: push eax
         // 0042f798: call _snprintf
      [-]ff8d85????????50ffb6
         // 0042f79d: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 0042f7a3: push eax
         // 0042f7a4: push ds:[esi+0x18a8]
      [-]ff83c41885c07528
         // 0042f7af: add esp, 0x18
         // 0042f7b2: test eax, eax
         // 0042f7b4: jnz 0x42f7de
      [-]ff83c404899e
         // 0042f7c1: add esp, 0x4
         // 0042f7c4: mov ds:[esi+0x18a8], ebx
      [-]8d431b5f5e5b8b4dfc33cde8
         // 0042f7ca: lea eax, ds:[ebx+0x1b]
         // 0042f7cd: pop edi
         // 0042f7ce: pop esi
         // 0042f7cf: pop ebx
         // 0042f7d0: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042f7d3: xor ecx, ebp
         // 0042f7d5: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 0042f7da: mov esp, ebp
         // 0042f7dc: pop ebp
         // 0042f7dd: retn 
      [-]85ff0f84
         // 005c1693: test edi, edi
         // 005c1695: jz 0x5c1891
      [-]8d85????????508d85????????5068
         // 0042f800: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 0042f806: push eax
         // 0042f807: lea eax, ss:[ebp+0xffffffffffffff7c]
         // 0042f80d: push eax
         // 0042f80e: push 0x45edf0
      [-]ff83c41083f8020f85
         // 0042f81a: add esp, 0x10
         // 0042f81d: cmp eax, 0x2
         // 0042f820: jnz 0x42f92c
      [-]8d85????????68
         // 0042f826: lea eax, ss:[ebp+0xffffffffffffff7c]
         // 0042f82c: push 0x45ee08
      [-]83c40885c0742d
         // 0042f837: add esp, 0x8
         // 0042f83a: test eax, eax
         // 0042f83c: jz 0x42f86b
      [-]6a1f8d85????????508d86??
         // 005541be: push 0x1f
         // 005541c0: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 005541c6: push eax
         // 005541c7: lea eax, ds:[esi+0x1808]
      [-]83c40c889e27
         // 005541d3: add esp, 0xc
         // 005541d6: mov b1 ds:[esi+0x1827], b1 bl
      [-]0000c786????????????????e9
         // 005541dc: mov ds:[esi+0x868], 0x1
         // 005541e6: jmp 0x55426e
      [-]8d85????????68
         // 0042f86b: lea eax, ss:[ebp+0xffffffffffffff7c]
         // 0042f871: push 0x45f30c
      [-]83c40885c074
         // 0042f87c: add esp, 0x8
         // 0042f87f: test eax, eax
         // 0042f881: jz 0x42f8ad
      [-]6a7f8d85????????508d86??
         // 00431283: push 0x7f
         // 00431285: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 0043128b: push eax
         // 0043128c: lea eax, ds:[esi+0x1828]
      [-]83c40c889ea7
         // 00431298: add esp, 0xc
         // 0043129b: mov b1 ds:[esi+0x18a7], b1 bl
      [-]0000c786????????????????
         // 004312a1: mov ds:[esi+0x894], 0x1
      [-]8d85????????50ffb6
         // 0042f8c5: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 0042f8cb: push eax
         // 0042f8cc: push ds:[esi+0x18a8]
      [-]ff83c40885c0
         // 0042f8d7: add esp, 0x8
         // 0042f8da: test eax, eax
      [-]8b7f0485ff0f85
         // 005242be: mov edi, ds:[edi+0x4]
         // 005242c1: test edi, edi
         // 005242c3: jnz 0x5241d0
      [-]5f5e8bc35b8b4dfc33cde8ff
         // 0042e7e9: pop edi
         // 0042e7ea: pop esi
         // 0042e7eb: mov eax, ebx
         // 0042e7ed: pop ebx
         // 0042e7ee: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042e7f1: xor ecx, ebp
         // 0042e7f3: call @__security_check_cookie@4
      [-]8be55dc3
         // 0042e7f8: mov esp, ebp
         // 0042e7fa: pop ebp
         // 0042e7fb: retn 
      [-]bb????????eb33
         // 005242dc: mov ebx, 0x1b
         // 005242e1: jmp 0x524316
      [-]ffb5????????e8
         // 0055429a: push ss:[ebp+0xfffffffffffffe78]
         // 005542a0: call 0x546540
      [-]ffbb????????eb17
         // 005542a5: mov ebx, 0x30
         // 005542aa: jmp 0x5542c3
      [-]ffb5????????e8
         // 0042e823: push ss:[ebp+0xfffffffffffffe78]
         // 0042e829: call 0x4209d0
      [-]ffbb????????
         // 0042e82e: mov ebx, 0x31
      [-]ff83c404c786
         // 0042f951: add esp, 0x4
         // 0042f954: mov ds:[esi+0x18a8], 0x0
      [-]8b4dfc8bc35f5e33cd5be8
         // 005542de: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 005542e1: mov eax, ebx
         // 005542e3: pop edi
         // 005542e4: pop esi
         // 005542e5: xor ecx, ebp
         // 005542e7: pop ebx
         // 005542e8: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 005542ed: mov esp, ebp
         // 005542ef: pop ebp
         // 005542f0: retn 
      [-]558bec81ec????????a1
         // 004e4390: push ebp
         // 004e4391: mov ebp, esp
         // 004e4393: sub esp, 0x194
         // 004e4399: mov eax, ds:[___security_cookie]
      [-]0033c58945fc568b75088d85????????506a02ff15
         // 004e439e: xor eax, ebp
         // 004e43a0: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004e43a3: push esi
         // 004e43a4: mov esi, ss:[ebp+0x8]
         // 004e43a7: lea eax, ss:[ebp+0xfffffffffffffe6c]
         // 004e43ad: push eax
         // 004e43ae: push 0x2
         // 004e43b0: call ds:[WSAStartup]
      [-]0085c07423
         // 004e43b6: test eax, eax
         // 004e43b8: jz 0x4e43dd
      [-]ff83c40cb8????????5e8b4dfc33cde8
         // 00554336: add esp, 0xc
         // 00554339: mov eax, 0x2
         // 0055433e: pop esi
         // 0055433f: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00554342: xor ecx, ebp
         // 00554344: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 00554349: mov esp, ebp
         // 0055434b: pop ebp
         // 0055434c: retn 
      [-]008b85????????3c027518
         // 0042e8c3: mov eax, ss:[ebp+0xfffffffffffffe6c]
         // 0042e8c9: cmp b1 al, b1 0x2
         // 0042e8cb: jnz 0x42e8e5
      [-]c1e80884c07511
         // 005243ad: shr eax, b1 0x8
         // 005243b0: test b1 al, b1 al
         // 005243b2: jnz 0x5243c5
      [-]33c05e8b4dfc33cde8
         // 0042e8d4: xor eax, eax
         // 0042e8d6: pop esi
         // 0042e8d7: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042e8da: xor ecx, ebp
         // 0042e8dc: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 0042e8e1: mov esp, ebp
         // 0042e8e3: pop ebp
         // 0042e8e4: retn 
      [-]ff8b4dfc83c40833cdb8????????5ee8
         // 00554380: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00554383: add esp, 0x8
         // 00554386: xor ecx, ebp
         // 00554388: mov eax, 0x2
         // 0055438d: pop esi
         // 0055438e: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 00554393: mov esp, ebp
         // 00554395: pop ebp
         // 00554396: retn 
      [-]558bec68
         // 0042fa20: push ebp
         // 0042fa21: mov ebp, esp
         // 0042fa23: push 0x1ab8
      [-]6a01ff15
         // 0042fa28: push 0x1
         // 0042fa2a: call ds:[0x605c14]
      [-]8bc883c40885c97507
         // 0042fa30: mov ecx, eax
         // 0042fa32: add esp, 0x8
         // 0042fa35: test ecx, ecx
         // 0042fa37: jnz 0x42fa40
      [-]b8????????5dc3
         // 00524409: mov eax, 0x1b
         // 0052440e: pop ebp
         // 0052440f: retn 
      [-]8b45088b008988
         // 004e4450: mov eax, ss:[ebp+0x8]
         // 004e4453: mov eax, ds:[eax]
         // 004e4455: mov ds:[eax+0x154], ecx
      [-]33c0c781
         // 004e4467: xor eax, eax
         // 004e4469: mov ds:[ecx+0x1eb8], 0x0
      [-]558bec538b5d08565733f68b038bb8
         // 004e44c0: push ebp
         // 004e44c1: mov ebp, esp
         // 004e44c3: push ebx
         // 004e44c4: mov ebx, ss:[ebp+0x8]
         // 004e44c7: push esi
         // 004e44c8: push edi
         // 004e44c9: xor esi, esi
         // 004e44cb: mov eax, ds:[ebx]
         // 004e44cd: mov edi, ds:[eax+0x154]
      [-]81c7????????0f1f80????????
         // 004e44d3: add edi, 0x1408
         // 004e44d9: nop ds:[eax+0x0]
      [-]83bf????????01750c
         // 00524480: cmp ds:[edi+0xfffffffffffff400], 0x1
         // 00524487: jnz 0x524495
      [-]6a015653e8
         // 004e44ee: push 0x1
         // 004e44f0: push esi
         // 004e44f1: push ebx
         // 004e44f2: call 0x4e4f20
      [-]000083c40c
         // 004e44f7: add esp, 0xc
      [-]833f01750c
         // 00524495: cmp ds:[edi], 0x1
         // 00524498: jnz 0x5244a6
      [-]6a015653e8
         // 004e44ff: push 0x1
         // 004e4501: push esi
         // 004e4502: push ebx
         // 004e4503: call 0x4e4fc0
      [-]000083c40c
         // 004e4508: add esp, 0xc
      [-]4683c70483fe287c
         // 005244a6: inc esi
         // 005244a7: add edi, 0x4
         // 005244aa: cmp esi, 0x28
         // 005244ad: jl 0x524480
      [-]5f5e5b5dc3
         // 005244af: pop edi
         // 005244b0: pop esi
         // 005244b1: pop ebx
         // 005244b2: pop ebp
         // 005244b3: retn 
      [-]558bec8b5508
         // 005c1a40: push ebp
         // 005c1a41: mov ebp, esp
         // 005c1a43: mov edx, ss:[ebp+0x8]
      [-]0f84eb000000
         // 005c1a4d: jz 0x5c1b3e
      [-]8b4d1081f9????????753c
         // 005244d3: mov ecx, ss:[ebp+0x10]
         // 005244d6: cmp ecx, 0xff
         // 005244dc: jnz 0x52451a
      [-]8b4d148d81????????83f813771a
         // 005244de: mov ecx, ss:[ebp+0x14]
         // 005244e1: lea eax, ds:[ecx+0xffffffffffffff14]
         // 005244e7: cmp eax, 0x13
         // 005244ea: ja 0x524506
      [-]ff750c68
         // 0042f793: push ss:[ebp+0xc]
         // 0042f796: push 0x45ecf0
      [-]ff83c4105dc3
         // 0042f7a1: add esp, 0x10
         // 0042f7a4: pop ebp
         // 0042f7a5: retn 
      [-]51ff750c68
         // 0042ea26: push ecx
         // 0042ea27: push ss:[ebp+0xc]
         // 0042ea2a: push 0x45dcf4
      [-]ff83c4105dc3
         // 0042ea35: add esp, 0x10
         // 0042ea38: pop ebp
         // 0042ea39: retn 
      [-]5681f9????????7507
         // 0052451a: push esi
         // 0052451b: cmp ecx, 0xfb
         // 00524521: jnz 0x52452a
      [-]81f9????????7507
         // 0052452a: cmp ecx, 0xfc
         // 00524530: jnz 0x524539
      [-]81f9????????7507
         // 00524539: cmp ecx, 0xfd
         // 0052453f: jnz 0x524548
      [-]81f9????????0f45c685c0744c
         // 0042ea6f: cmp ecx, 0xfe
         // 0042ea75: cmovnz eax, esi
         // 0042ea78: test eax, eax
         // 0042ea7a: jz 0x42eac8
      [-]8b4d1483f9277f21
         // 0052455c: mov ecx, ss:[ebp+0x14]
         // 0052455f: cmp ecx, 0x27
         // 00524562: jg 0x524585
      [-]85f67523
         // 0042ea8b: test esi, esi
         // 0042ea8d: jnz 0x42eab2
      [-]5150ff750c68
         // 0042ea8f: push ecx
         // 0042ea90: push eax
         // 0042ea91: push ss:[ebp+0xc]
         // 0042ea94: push 0x45dd14
      [-]ff83c4145e5dc3
         // 0042ea9f: add esp, 0x14
         // 0042eaa2: pop esi
         // 0042eaa3: pop ebp
         // 0042eaa4: retn 
      [-]81f9????????75e2
         // 00524585: cmp ecx, 0xff
         // 0052458b: jnz 0x52456f
      [-]5650ff750c68
         // 0042eab2: push esi
         // 0042eab3: push eax
         // 0042eab4: push ss:[ebp+0xc]
         // 0042eab7: push 0x45dd08
      [-]ff83c4145e5dc3
         // 0042eac2: add esp, 0x14
         // 0042eac5: pop esi
         // 0042eac6: pop ebp
         // 0042eac7: retn 
      [-]ff751451ff750c68
         // 0042eac8: push ss:[ebp+0x14]
         // 0042eacb: push ecx
         // 0042eacc: push ss:[ebp+0xc]
         // 0042eacf: push 0x45dd20
      [-]ff83c4145e
         // 0042eada: add esp, 0x14
         // 0042eadd: pop esi
      [-]558bec51568b7508
         // 004e4630: push ebp
         // 004e4631: mov ebp, esp
         // 004e4633: push ecx
         // 004e4634: push esi
         // 004e4635: mov esi, ss:[ebp+0x8]
      [-]8b4d0c535785c90f84
         // 005c1b56: mov ecx, ss:[ebp+0xc]
         // 005c1b59: push ebx
         // 005c1b5d: push edi
         // 005c1b5e: test ecx, ecx
         // 005c1b60: jz 0x5c1c53
      [-]83f93cba
         // 004e465a: cmp ecx, 0x3c
         // 004e465d: mov edx, 0x60b4b0
      [-]0f45c25068
         // 004e4667: cmovnz eax, edx
         // 004e466a: push eax
         // 004e466b: push 0x60ad80
      [-]1483c40c83
         // 004e4679: add esp, 0xc
         // 004e467c: cmp edi, 0x3
      [-]ff83c40883
         // 0042eb62: add esp, 0x8
         // 0042eb65: cmp edi, 0x27
      [-]83c40c83f827770e
         // 0042fcad: add esp, 0xc
         // 0042fcb0: cmp eax, 0x27
         // 0042fcb3: ja 0x42fcc3
      [-]3d????????720e
         // 00524693: cmp eax, 0xec
         // 00524698: jb 0x5246a8
      [-]ff83c40c68
         // 0042fce4: add esp, 0xc
         // 0042fce7: push 0x45ed68
      [-]ff83c408
         // 0042fcf2: add esp, 0x8
      [-]ff83c4085f5b5e8be55dc3
         // 0042ec00: add esp, 0x8
         // 0042ec03: pop edi
         // 0042ec04: pop ebx
         // 0042ec05: pop esi
         // 0042ec06: mov esp, ebp
         // 0042ec08: pop ebp
         // 0042ec09: retn 
      [-]80f92777
         // 0042ec0f: cmp b1 cl, b1 0x27
         // 0042ec12: ja 0x42ec45
      [-]ff83c408
         // 0042fa08: add esp, 0x8
      [-]3c180f84
         // 004e47f4: cmp b1 al, b1 0x18
         // 004e47f6: jz 0x4e489e
      [-]3c230f84
         // 004e47fc: cmp b1 al, b1 0x23
         // 004e47fe: jz 0x4e489e
      [-]3c27742c
         // 0052477d: cmp b1 al, b1 0x27
         // 0052477f: jz 0x5247ad
      [-]bf????????
         // 004e4808: mov edi, 0x2
      [-]ff4783c40c3b
         // 005c1d32: inc edi
         // 005c1d33: add esp, 0xc
         // 005c1d36: cmp edi, ss:[ebp+0x8]
      [-]ffbf????????83c408
         // 004e4849: mov edi, 0x3
         // 004e484e: add esp, 0x8
      [-]8bc183e800741d
         // 005c1d6a: mov eax, ecx
         // 005c1d6c: sub eax, 0x0
         // 005c1d6f: jz 0x5c1d8e
      [-]83e8017411
         // 005247de: sub eax, 0x1
         // 005247e1: jz 0x5247f4
      [-]ff83c40ceb15
         // 0042ed0f: add esp, 0xc
         // 0042ed12: jmp 0x42ed29
      [-]ff83c408
         // 0042ed26: add esp, 0x8
      [-]837d0c00740e
         // 00524826: cmp ss:[ebp+0xc], 0x0
         // 0052482a: jz 0x52483a
      [-]ff83c408
         // 0042ed57: add esp, 0x8
      [-]5e8be55dc3
         // 0052483c: pop esi
         // 0052483d: mov esp, ebp
         // 0052483f: pop ebp
         // 00524840: retn 
      [-]558bec56
         // 0042ed80: push ebp
         // 0042ed81: mov ebp, esp
         // 0042ed83: push esi
      [-]8b7d088b078b
         // 0042ed85: mov edi, ss:[ebp+0x8]
         // 0042ed88: mov eax, ds:[edi]
         // 0042ed8a: mov esi, ds:[eax+0x8664]
      [-]83e80074
         // 005c1e5e: sub eax, 0x0
         // 005c1e61: jz 0x5c1e7c
      [-]83e80175
         // 00524897: sub eax, 0x1
         // 0052489a: jnz 0x5248e6
      [-]08????????89
         // 005248a4: mov ds:[edx+0x408], eax
      [-]0804000083
         // 005248bf: sub edx, 0x0
      [-]08????????89
         // 005248d0: mov ds:[esi+eax*0x4], edx
      [-]08100000
      [-]68????????57e8
         // 005248d8: push 0xfc
         // 005248dd: push edi
         // 005248de: call 0x524b40
      [-]02000083c40c
         // 005248e3: add esp, 0xc
      [-]00000175
         // 005248fd: jnz 0x5248d7
      [-]558bec8b55088b4d0c568b028bb0
         // 004e4a30: push ebp
         // 004e4a31: mov ebp, esp
         // 004e4a33: mov edx, ss:[ebp+0x8]
         // 004e4a36: mov ecx, ss:[ebp+0xc]
         // 004e4a39: push esi
         // 004e4a3a: mov eax, ds:[edx]
         // 004e4a3c: mov esi, ds:[eax+0x154]
      [-]8b448e0883e8017466
         // 004e4a42: mov eax, ds:[esi+ecx*0x4]
         // 004e4a46: sub eax, 0x1
         // 004e4a49: jz 0x4e4ab1
      [-]83e8017437
         // 0052493b: sub eax, 0x1
         // 0052493e: jz 0x524977
      [-]83e8017573
         // 00524940: sub eax, 0x1
         // 00524943: jnz 0x5249b8
      [-]8b848e0804000083e8007445
         // 00524945: mov eax, ds:[esi+ecx*0x4]
         // 0052494c: sub eax, 0x0
         // 0052494f: jz 0x524996
      [-]83e8017562
         // 00524951: sub eax, 0x1
         // 00524954: jnz 0x5249b8
      [-]5168????????52c7448e08????????89848e08040000e8cf01000083c40c5e5dc3
         // 00524956: push ecx
         // 00524957: push 0xfb
         // 0052495c: push edx
         // 0052495d: mov ds:[esi+ecx*0x4], 0x2
         // 00524965: mov ds:[esi+ecx*0x4], eax
         // 0052496c: call 0x524b40
         // 00524971: add esp, 0xc
         // 00524974: pop esi
         // 00524975: pop ebp
         // 00524976: retn 
      [-]8b848e0804000083e8007413
         // 00524977: mov eax, ds:[esi+ecx*0x4]
         // 0052497e: sub eax, 0x0
         // 00524981: jz 0x524996
      [-]83e8017530
         // 00524983: sub eax, 0x1
         // 00524986: jnz 0x5249b8
      [-]89448e0889848e080400005e5dc3
         // 00524988: mov ds:[esi+ecx*0x4], eax
         // 0052498c: mov ds:[esi+ecx*0x4], eax
         // 00524993: pop esi
         // 00524994: pop ebp
         // 00524995: retn 
      [-]c7448e08????????5e5dc3
         // 00524996: mov ds:[esi+ecx*0x4], 0x0
         // 0052499e: pop esi
         // 0052499f: pop ebp
         // 005249a0: retn 
      [-]5168????????52c7448e08????????e88b01000083c40c
         // 005249a1: push ecx
         // 005249a2: push 0xfc
         // 005249a7: push edx
         // 005249a8: mov ds:[esi+ecx*0x4], 0x0
         // 005249b0: call 0x524b40
         // 005249b5: add esp, 0xc
      [-]558bec8b5508568b028bb0
         // 004e4ad0: push ebp
         // 004e4ad1: mov ebp, esp
         // 004e4ad3: mov edx, ss:[ebp+0x8]
         // 004e4ad6: push esi
         // 004e4ad7: mov eax, ds:[edx]
         // 004e4ad9: mov esi, ds:[eax+0x154]
      [-]8b450c8b8c86080c000083e9000f8481000000
         // 004e4adf: mov eax, ss:[ebp+0xc]
         // 004e4ae2: mov ecx, ds:[esi+eax*0x4]
         // 004e4ae9: sub ecx, 0x0
         // 004e4aec: jz 0x4e4b73
      [-]83e9027439
         // 005249e2: sub ecx, 0x2
         // 005249e5: jz 0x524a20
      [-]83e9017566
         // 005249e7: sub ecx, 0x1
         // 005249ea: jnz 0x524a52
      [-]8b8c860810000083e900741a
         // 005249ec: mov ecx, ds:[esi+eax*0x4]
         // 005249f3: sub ecx, 0x0
         // 005249f6: jz 0x524a12
      [-]83e9017555
         // 005249f8: sub ecx, 0x1
         // 005249fb: jnz 0x524a52
      [-]c78486080c0000????????898c86081000005e5dc3
         // 005249fd: mov ds:[esi+eax*0x4], 0x1
         // 00524a08: mov ds:[esi+eax*0x4], ecx
         // 00524a0f: pop esi
         // 00524a10: pop ebp
         // 00524a11: retn 
      [-]c78486080c0000????????5e5dc3
         // 00524a12: mov ds:[esi+eax*0x4], 0x0
         // 00524a1d: pop esi
         // 00524a1e: pop ebp
         // 00524a1f: retn 
      [-]8b8c860810000083e9007429
         // 00524a20: mov ecx, ds:[esi+eax*0x4]
         // 00524a27: sub ecx, 0x0
         // 00524a2a: jz 0x524a55
      [-]83e9017521
         // 00524a2c: sub ecx, 0x1
         // 00524a2f: jnz 0x524a52
      [-]c78486080c0000????????898c8608100000
         // 00524a31: mov ds:[esi+eax*0x4], 0x3
         // 00524a3c: mov ds:[esi+eax*0x4], ecx
      [-]5068????????52e8f100000083c40c
         // 00524a43: push eax
         // 00524a44: push 0xfe
         // 00524a49: push edx
         // 00524a4a: call 0x524b40
         // 00524a4f: add esp, 0xc
      [-]c78486080c0000????????5e5dc3
         // 00524a55: mov ds:[esi+eax*0x4], 0x1
         // 00524a60: pop esi
         // 00524a61: pop ebp
         // 00524a62: retn 
      [-]83bc86081400000175d6
         // 00524a63: cmp ds:[esi+eax*0x4], 0x1
         // 00524a6b: jnz 0x524a43
      [-]5068????????52c78486080c0000????????e8bc00000083c40c5e5dc3
         // 00524a6d: push eax
         // 00524a6e: push 0xfd
         // 00524a73: push edx
         // 00524a74: mov ds:[esi+eax*0x4], 0x1
         // 00524a7f: call 0x524b40
         // 00524a84: add esp, 0xc
         // 00524a87: pop esi
         // 00524a88: pop ebp
         // 00524a89: retn 
      [-]558bec8b55088b4d0c568b028bb0
         // 004e4ba0: push ebp
         // 004e4ba1: mov ebp, esp
         // 004e4ba3: mov edx, ss:[ebp+0x8]
         // 004e4ba6: mov ecx, ss:[ebp+0xc]
         // 004e4ba9: push esi
         // 004e4baa: mov eax, ds:[edx]
         // 004e4bac: mov esi, ds:[eax+0x154]
      [-]8b848e080c000083e801746f
         // 004e4bb2: mov eax, ds:[esi+ecx*0x4]
         // 004e4bb9: sub eax, 0x1
         // 004e4bbc: jz 0x4e4c2d
      [-]83e801743a
         // 00524aae: sub eax, 0x1
         // 00524ab1: jz 0x524aed
      [-]83e801757f
         // 00524ab3: sub eax, 0x1
         // 00524ab6: jnz 0x524b37
      [-]8b848e0810000083e800744b
         // 00524ab8: mov eax, ds:[esi+ecx*0x4]
         // 00524abf: sub eax, 0x0
         // 00524ac2: jz 0x524b0f
      [-]83e801756e
         // 00524ac4: sub eax, 0x1
         // 00524ac7: jnz 0x524b37
      [-]5168????????52c7848e080c0000????????89848e08100000e85900000083c40c5e5dc3
         // 00524ac9: push ecx
         // 00524aca: push 0xfd
         // 00524acf: push edx
         // 00524ad0: mov ds:[esi+ecx*0x4], 0x2
         // 00524adb: mov ds:[esi+ecx*0x4], eax
         // 00524ae2: call 0x524b40
         // 00524ae7: add esp, 0xc
         // 00524aea: pop esi
         // 00524aeb: pop ebp
         // 00524aec: retn 
      [-]8b848e0810000083e8007416
         // 00524aed: mov eax, ds:[esi+ecx*0x4]
         // 00524af4: sub eax, 0x0
         // 00524af7: jz 0x524b0f
      [-]83e8017539
         // 00524af9: sub eax, 0x1
         // 00524afc: jnz 0x524b37
      [-]89848e080c000089848e081000005e5dc3
         // 00524afe: mov ds:[esi+ecx*0x4], eax
         // 00524b05: mov ds:[esi+ecx*0x4], eax
         // 00524b0c: pop esi
         // 00524b0d: pop ebp
         // 00524b0e: retn 
      [-]c7848e080c0000????????5e5dc3
         // 00524b0f: mov ds:[esi+ecx*0x4], 0x0
         // 00524b1a: pop esi
         // 00524b1b: pop ebp
         // 00524b1c: retn 
      [-]5168????????52c7848e080c0000????????e80c00000083c40c
         // 00524b1d: push ecx
         // 00524b1e: push 0xfe
         // 00524b23: push edx
         // 00524b24: mov ds:[esi+ecx*0x4], 0x0
         // 00524b2f: call 0x524b40
         // 00524b34: add esp, 0xc
      [-]558bec8b4510538b5d0c568b7508576a0088450a8d45088b3e6a0350ffb6
         // 00520270: push ebp
         // 00520271: mov ebp, esp
         // 00520273: mov eax, ss:[ebp+0x10]
         // 00520276: push ebx
         // 00520277: mov ebx, ss:[ebp+0xc]
         // 0052027a: push esi
         // 0052027b: mov esi, ss:[ebp+0x8]
         // 0052027e: push edi
         // 0052027f: push 0x0
         // 00520281: mov b1 ss:[ebp+0xa], b1 al
         // 00520284: lea eax, ss:[ebp+0x8]
         // 00520287: mov edi, ds:[esi]
         // 00520289: push 0x3
         // 0052028b: push eax
         // 0052028c: push ds:[esi+0x130]
      [-]c64508ff885d09ff1500
         // 00520292: mov b1 ss:[ebp+0x8], b1 0xff
         // 00520296: mov b1 ss:[ebp+0x9], b1 bl
         // 00520299: call ds:[send]
      [-]85c07915
         // 0052029f: test eax, eax
         // 005202a1: jns 0x5202b8
      [-]ff83c40c
         // 0042f0a5: add esp, 0xc
      [-]ff75105368
         // 004301b8: push ss:[ebp+0x10]
         // 004301bb: push ebx
         // 004301bc: push 0x45ed38
      [-]ffff83c4105f5e5b5dc3
         // 004301c8: add esp, 0x10
         // 004301cb: pop edi
         // 004301cc: pop esi
         // 004301cd: pop ebx
         // 004301ce: pop ebp
         // 004301cf: retn 
      [-]558bec83ec
         // 00431bd0: push ebp
         // 00431bd1: mov ebp, esp
         // 00431bd3: sub esp, 0x14
      [-]8945f08d45
         // 00431c20: mov b2 ss:[ebp+0xfffffffffffffff0], b2 ax
         // 00431c24: lea eax, ss:[ebp+0xffffffffffffffec]
      [-]4083c40c83f80176
         // 00431c2f: inc eax
         // 00431c30: add esp, 0xc
         // 00431c33: cmp eax, 0x1
         // 00431c36: jbe 0x431c6f
      [-]5b8be55dc3
         // 004e4db4: pop ebx
         // 004e4db5: mov esp, ebp
         // 004e4db7: pop ebp
         // 004e4db8: retn 
      [-]558bec837d10018b550c568b75088b068b88
         // 004e4f20: push ebp
         // 004e4f21: mov ebp, esp
         // 004e4f23: cmp ss:[ebp+0x10], 0x1
         // 004e4f27: mov edx, ss:[ebp+0xc]
         // 004e4f2a: push esi
         // 004e4f2b: mov esi, ss:[ebp+0x8]
         // 004e4f2e: mov eax, ds:[esi]
         // 004e4f30: mov ecx, ds:[eax+0x154]
      [-]8b4491087541
         // 004e4f36: mov eax, ds:[ecx+edx*0x4]
         // 004e4f3a: jnz 0x4e4f7d
      [-]83e8007422
         // 00524c7c: sub eax, 0x0
         // 00524c7f: jz 0x524ca3
      [-]83e8027446
         // 00524c81: sub eax, 0x2
         // 00524c84: jz 0x524ccc
      [-]83e801756e
         // 00524c86: sub eax, 0x1
         // 00524c89: jnz 0x524cf9
      [-]83bc9108????????7564
         // 00524c8b: cmp ds:[ecx+edx*0x4], 0x0
         // 00524c93: jnz 0x524cf9
      [-]c7849108040000????????5e5dc3
         // 00524c95: mov ds:[ecx+edx*0x4], 0x1
         // 00524ca0: pop esi
         // 00524ca1: pop ebp
         // 00524ca2: retn 
      [-]5268????????56c7449108????????e8
         // 004e4f63: push edx
         // 004e4f64: push 0xfb
         // 004e4f69: push esi
         // 004e4f6a: mov ds:[ecx+edx*0x4], 0x2
         // 004e4f72: call 0x4e4c50
      [-]ffff83c40c5e5dc3
         // 004e4f77: add esp, 0xc
         // 004e4f7a: pop esi
         // 004e4f7b: pop ebp
         // 004e4f7c: retn 
      [-]83e8017420
         // 00524cbd: sub eax, 0x1
         // 00524cc0: jz 0x524ce2
      [-]83e80174c4
         // 00524cc2: sub eax, 0x1
         // 00524cc5: jz 0x524c8b
      [-]83e801752d
         // 00524cc7: sub eax, 0x1
         // 00524cca: jnz 0x524cf9
      [-]8b84910804000083e8017521
         // 00524ccc: mov eax, ds:[ecx+edx*0x4]
         // 00524cd3: sub eax, 0x1
         // 00524cd6: jnz 0x524cf9
      [-]898491080400005e5dc3
         // 00524cd8: mov ds:[ecx+edx*0x4], eax
         // 00524cdf: pop esi
         // 00524ce0: pop ebp
         // 00524ce1: retn 
      [-]5268????????56c7449108????????e8
         // 004e4fa2: push edx
         // 004e4fa3: push 0xfc
         // 004e4fa8: push esi
         // 004e4fa9: mov ds:[ecx+edx*0x4], 0x3
         // 004e4fb1: call 0x4e4c50
      [-]ffff83c40c
         // 004e4fb6: add esp, 0xc
      [-]558bec837d10018b550c568b75088b068b88
         // 004e4fc0: push ebp
         // 004e4fc1: mov ebp, esp
         // 004e4fc3: cmp ss:[ebp+0x10], 0x1
         // 004e4fc7: mov edx, ss:[ebp+0xc]
         // 004e4fca: push esi
         // 004e4fcb: mov esi, ss:[ebp+0x8]
         // 004e4fce: mov eax, ds:[esi]
         // 004e4fd0: mov ecx, ds:[eax+0x154]
      [-]8b8491080c00007544
         // 004e4fd6: mov eax, ds:[ecx+edx*0x4]
         // 004e4fdd: jnz 0x4e5023
      [-]83e8007422
         // 00524d1f: sub eax, 0x0
         // 00524d22: jz 0x524d46
      [-]83e8027449
         // 00524d24: sub eax, 0x2
         // 00524d27: jz 0x524d72
      [-]83e8017574
         // 00524d29: sub eax, 0x1
         // 00524d2c: jnz 0x524da2
      [-]83bc910810000000756a
         // 00524d2e: cmp ds:[ecx+edx*0x4], 0x0
         // 00524d36: jnz 0x524da2
      [-]c7849108100000????????5e5dc3
         // 00524d38: mov ds:[ecx+edx*0x4], 0x1
         // 00524d43: pop esi
         // 00524d44: pop ebp
         // 00524d45: retn 
      [-]5268????????56c78491080c0000????????e8
         // 004e5006: push edx
         // 004e5007: push 0xfd
         // 004e500c: push esi
         // 004e500d: mov ds:[ecx+edx*0x4], 0x2
         // 004e5018: call 0x4e4c50
      [-]ffff83c40c5e5dc3
         // 004e501d: add esp, 0xc
         // 004e5020: pop esi
         // 004e5021: pop ebp
         // 004e5022: retn 
      [-]83e8017420
         // 00524d63: sub eax, 0x1
         // 00524d66: jz 0x524d88
      [-]83e80174c1
         // 00524d68: sub eax, 0x1
         // 00524d6b: jz 0x524d2e
      [-]83e8017530
         // 00524d6d: sub eax, 0x1
         // 00524d70: jnz 0x524da2
      [-]8b84910810000083e8017524
         // 00524d72: mov eax, ds:[ecx+edx*0x4]
         // 00524d79: sub eax, 0x1
         // 00524d7c: jnz 0x524da2
      [-]898491081000005e5dc3
         // 00524d7e: mov ds:[ecx+edx*0x4], eax
         // 00524d85: pop esi
         // 00524d86: pop ebp
         // 00524d87: retn 
      [-]5268????????56c78491080c0000????????e8
         // 004e5048: push edx
         // 004e5049: push 0xfe
         // 004e504e: push esi
         // 004e504f: mov ds:[ecx+edx*0x4], 0x3
         // 004e505a: call 0x4e4c50
      [-]ffff83c40c
         // 004e505f: add esp, 0xc
      [-]558bec81ec????????a1
         // 00430050: push ebp
         // 00430051: mov ebp, esp
         // 00430053: sub esp, 0x90c
         // 00430059: mov eax, ds:[___security_cookie]
      [-]0033c58945fc5356578b7d0889bd????????8b1f899d????????8bb3
         // 0043005e: xor eax, ebp
         // 00430060: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00430063: push ebx
         // 00430064: push esi
         // 00430065: push edi
         // 00430066: mov edi, ss:[ebp+0x8]
         // 00430069: mov ss:[ebp+0xfffffffffffff6f4], edi
         // 0043006f: mov ebx, ds:[edi]
         // 00430071: mov ss:[ebp+0xfffffffffffff6f8], ebx
         // 00430077: mov esi, ds:[ebx+0x8664]
      [-]83c002508d86
         // 00430089: add eax, 0x2
         // 0043008c: push eax
         // 0043008d: lea eax, ds:[esi+0x18ac]
      [-]506a3c53e8
         // 00430093: push eax
         // 00430094: push 0x3c
         // 00430096: push ebx
         // 00430097: call 0x42f860
      [-]ffff8b86
         // 0043009c: mov eax, ds:[esi+0x1aac]
      [-]0fb608408986
         // 004300a5: movzx ecx, b1 ds:[eax]
         // 004300a8: inc eax
         // 004300a9: mov ds:[esi+0x1aac], eax
      [-]83f9180f84
         // 004300af: cmp ecx, 0x18
         // 004300b2: jz 0x430208
      [-]83f9230f84
         // 00524e18: cmp ecx, 0x23
         // 00524e1b: jz 0x524f44
      [-]83f9270f85
         // 00524e21: cmp ecx, 0x27
         // 00524e24: jnz 0x524ff6
      [-]6a005168????????68????????68
         // 0052055a: push 0x0
         // 0052055c: push ecx
         // 0052055d: push 0xfa
         // 00520562: push 0xff
         // 00520567: push 0x6332a4
      [-]8d85????????68????????50e8
         // 0052056c: lea eax, ss:[ebp+0xfffffffffffff6fc]
         // 00520572: push 0x800
         // 00520577: push eax
         // 00520578: call _snprintf
      [-]83c41cbf????????b8????????85f6
         // 00520583: add esp, 0x1c
         // 00520586: mov edi, 0x4
         // 0052058b: mov eax, 0x800
         // 00520590: test esi, esi
      [-]8b168bca8d5901
         // 00524e64: mov edx, ds:[esi]
         // 00524e66: mov ecx, edx
         // 00524e68: lea ebx, ds:[ecx+0x1]
      [-]8a014184c075f9
         // 00524e70: mov b1 al, b1 ds:[ecx]
         // 00524e72: inc ecx
         // 00524e73: test b1 al, b1 al
         // 00524e75: jnz 0x524e70
      [-]2bcb8d5f0103d981fb????????73
         // 00524e77: sub ecx, ebx
         // 00524e79: lea ebx, ds:[edi+0x1]
         // 00524e7c: add ebx, ecx
         // 00524e7e: cmp ebx, 0x7fa
         // 00524e84: jnb 0x524ed1
      [-]8d85????????50
         // 004e518d: lea eax, ss:[ebp+0xffffffffffffff7c]
         // 004e5193: push eax
      [-]8d85????????506a00b8????????2bc768
         // 004e5196: lea eax, ss:[ebp+0xfffffffffffffefc]
         // 004e519c: push eax
         // 004e519d: push 0x0
         // 004e519f: mov eax, 0x800
         // 004e51a4: sub eax, edi
         // 004e51a6: push 0x60aed8
      [-]508d85????????03c750e8
         // 004e51ab: push eax
         // 004e51ac: lea eax, ss:[ebp+0xfffffffffffff6fc]
         // 004e51b2: add eax, edi
         // 004e51b4: push eax
         // 004e51b5: call _snprintf
      [-]8b760485f6
         // 00524ed1: mov esi, ds:[esi+0x4]
         // 00524ed4: test esi, esi
         // 00524ed6: jnz 0x524e64

  }
  condition:
    all of them
}
