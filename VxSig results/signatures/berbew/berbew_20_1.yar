rule berbew_20_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         9090909090
         // 0042e00e: nop 
         // 0042e00f: nop 
         // 0042e011: nop 
         // 0042e017: nop 
         // 0042e01d: nop 

  }
  condition:
    all of them
}
