rule berbew_30_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         90909090
         // 00432000: nop 
         // 00432003: nop 
         // 00432004: nop 
         // 00432012: nop 
      [-]9090909090
         // 0043201b: nop 
         // 0043201c: nop 
         // 0043201d: nop 
         // 0043201e: nop 
         // 0043201f: nop 

  }
  condition:
    all of them
}
