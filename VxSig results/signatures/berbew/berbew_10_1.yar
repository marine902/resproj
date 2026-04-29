rule berbew_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         90909090
         // 0043300c: nop 
         // 0043300e: nop 
         // 0043300f: nop 
         // 00433010: nop 

  }
  condition:
    all of them
}
