rule softpulse_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec83ec10
         // 004667e2: push ebp
         // 004667e3: mov ebp, esp
         // 004667e5: sub esp, 0x10

  }
  condition:
    all of them
}
