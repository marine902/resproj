rule crytex_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         5668????????ffb5????????e802000000
         // 0050e614: push esi
         // 0050e615: push 0x12c
         // 0050e61a: push ss:[ebp+0x401056]
         // 0050e620: call 0x50e627

  }
  condition:
    all of them
}
