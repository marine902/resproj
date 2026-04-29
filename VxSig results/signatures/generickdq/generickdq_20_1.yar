rule generickdq_20_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         85c07505
         // 1400191d7: test rax, rax
         // 1400191da: jnz 0x1400191e1
      [-]83cfffeb
         // 00427905: or edi, 0xffffffffffffffff
         // 00427908: jmp 0x42791c

  }
  condition:
    all of them
}
