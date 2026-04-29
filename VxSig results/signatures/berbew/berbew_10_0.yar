rule berbew_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         9090909090
         // 00432010: nop 
         // 00432011: nop 
         // 00432012: nop 
         // 00432013: nop 
         // 00432015: nop 

  }
  condition:
    all of them
}
