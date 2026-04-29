rule softcnapp_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         ff762ce8
         // 0044c3bb: push ds:[esi+0x2c]
         // 0044c3be: call ?to_integer_size@__crt_stdio_output@@YAIW4length_modifier@1@@Z
      [-]83e9017478
         // 0044c3c8: sub ecx, 0x1
         // 0044c3cb: jz 0x44c445
      [-]83e9017456
         // 004483a1: sub ecx, 0x1
         // 004483a4: jz 0x4483fc
      [-]4983e9017433
         // 004483a6: dec ecx
         // 004483a7: sub ecx, 0x1
         // 004483aa: jz 0x4483df
      [-]c1e804a8018b46147405
         // 0044c412: shr eax, b1 0x4
         // 0044c415: test b1 al, b1 0x1
         // 0044c417: mov eax, ds:[esi+0x14]
         // 0044c41a: jz 0x44c421
      [-]8b462083461404c1e804a801
         // 0044c428: mov eax, ds:[esi+0x20]
         // 0044c42b: add ds:[esi+0x14], 0x4
         // 0044c42f: shr eax, b1 0x4
         // 0044c432: test b1 al, b1 0x1
      [-]578b7e20
         // 00448437: push edi
         // 00448438: mov edi, ds:[esi+0x20]
      [-]c1e804a8017417
         // 0044843d: shr eax, b1 0x4
         // 00448440: test b1 al, b1 0x1
         // 00448442: jz 0x44845b
      [-]f7d983d200f7da83cf40897e20
         // 0044844e: neg ecx
         // 00448450: adc edx, 0x0
         // 00448453: neg edx
         // 00448455: or edi, 0x40
         // 00448458: mov ds:[esi+0x20], edi
      [-]837e2800
         // 004ceb61: cmp ds:[esi+0x28], 0x0
      [-]0bc27504
         // 0044847e: or eax, edx
         // 00448480: jnz 0x448486
      [-]836620df
         // 00448482: and ds:[esi+0x20], 0xffffffffffffffdf
      [-]83fb08750b
         // 0044848c: cmp ebx, 0x8
         // 0044848f: jnz 0x44849c
      [-]8b4620c1e807a801741a
         // 004484a4: mov eax, ds:[esi+0x20]
         // 004484a7: shr eax, b1 0x7
         // 004484aa: test b1 al, b1 0x1
         // 004484ac: jz 0x4484c8
      [-]837e38007408
         // 004484ae: cmp ds:[esi+0x38], 0x0
         // 004484b2: jz 0x4484bc
      [-]8b4634803830740c
         // 004484b4: mov eax, ds:[esi+0x34]
         // 004484b7: cmp b1 ds:[eax], b1 0x30
         // 004484ba: jz 0x4484c8
      [-]ff4e348b4e34c60130
         // 004cebc2: dec ds:[esi+0x34]
         // 004cebc5: mov ecx, ds:[esi+0x34]
         // 004cebc8: mov b1 ds:[ecx], b1 0x30
      [-]c1e805a8017409
         // 00448549: shr eax, b1 0x5
         // 0044854c: test b1 al, b1 0x1
         // 0044854e: jz 0x448559
      [-]81ca????????895120
         // 00448550: or edx, 0x80
         // 00448556: mov ds:[ecx+0x20], edx
      [-]6a006a08e824feffffc3
         // 00448559: push 0x0
         // 0044855b: push 0x8
         // 0044855d: call 0x448386
         // 00448562: retn 
      [-]8945f88945f48d45f850ff750c8d45f450e8
         // 0044e401: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0044e404: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0044e407: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0044e40a: push eax
         // 0044e40b: push ss:[ebp+0xc]
         // 0044e411: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0044e414: push eax
         // 0044e415: call ??$?RV_lambda_51b6e8b1eb166f2a3faf91f424b38130_@@AAV_lambda_6250bd4b2a391816dd638c3bf72b0bcb_@@V_lambda_0b5a4a3e68152e1d9b943535f5f47bed_@@@?$__crt_seh_guarded_call@X@@QAEX$$QAV_lambda_51b6e8b1eb166f2a3faf91f424b38130_@@AAV_lambda_6250bd4b2a391816dd638c3bf72b0bcb_@@$$QAV_lambda_0b5a4a3e68152e1d9b943535f5f47bed_@@@Z
      [-]558bec83ec0c8b45088d4dff8945f88945f48d45f850ff750c8d45f450e8
         // 0042706f: push ebp
         // 00427070: mov ebp, esp
         // 00427072: sub esp, 0xc
         // 00427075: mov eax, ss:[ebp+0x8]
         // 00427078: lea ecx, ss:[ebp+0xffffffffffffffff]
         // 0042707b: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0042707e: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00427081: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00427084: push eax
         // 00427085: push ss:[ebp+0xc]
         // 00427088: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0042708b: push eax
         // 0042708c: call ??$?RV_lambda_3518db117f0e7cdb002338c5d3c47b6c_@@AAV_lambda_b2ea41f6bbb362cd97d94c6828d90b61_@@V_lambda_abdedf541bb04549bc734292b4a045d4_@@@?$__crt_seh_guarded_call@X@@QAEX$$QAV_lambda_3518db117f0e7cdb002338c5d3c47b6c_@@AAV_lambda_b2ea41f6bbb362cd97d94c6828d90b61_@@$$QAV_lambda_abdedf541bb04549bc734292b4a045d4_@@@Z
      [-]feffff8be55dc3
         // 00427091: mov esp, ebp
         // 00427093: pop ebp
         // 00427094: retn 
      [-]feffff8be55dc3
         // 0044fc3a: mov esp, ebp
         // 0044fc3c: pop ebp
         // 0044fc3d: retn 
      [-]558bec568b750c8b063b05
         // 004528ed: push ebp
         // 004528ee: mov ebp, esp
         // 004528f0: push esi
         // 004528f1: mov esi, ss:[ebp+0xc]
         // 004528f4: mov eax, ds:[esi]
         // 004528f6: cmp eax, ds:[0x60f740]
      [-]8b4d08a1
         // 004528fe: mov ecx, ss:[ebp+0x8]
         // 00452901: mov eax, ds:[0x60e900]
      [-]8581????????7507
         // 00452906: test ds:[ecx+0x350], eax
         // 0045290c: jnz 0x452915
      [-]558bec568b750c8b063b05
         // 0045291a: push ebp
         // 0045291b: mov ebp, esp
         // 0045291d: push esi
         // 0045291e: mov esi, ss:[ebp+0xc]
         // 00452921: mov eax, ds:[esi]
         // 00452923: cmp eax, ds:[0x60e7d8]
      [-]8b4d08a1
         // 0045292b: mov ecx, ss:[ebp+0x8]
         // 0045292e: mov eax, ds:[0x60e900]
      [-]8581????????7507
         // 00452933: test ds:[ecx+0x350], eax
         // 00452939: jnz 0x452942

  }
  condition:
    all of them
}
