rule pioneer_30_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         5060e8edffffffc20400
         // 00767ed9: push eax
         // 00767eda: pusha 
         // 00767edb: call 0x767ecd
         // 00767ee0: retn b2 0x4

  }
  condition:
    all of them
}
