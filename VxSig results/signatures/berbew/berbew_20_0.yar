rule berbew_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         90909090
         // 0043200c: nop 
         // 0043200d: nop 
         // 0043200e: nop 
         // 0043200f: nop 

  }
  condition:
    all of them
}
