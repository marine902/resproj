rule berbew
{
    meta:
        family = "berbew"
        nb_samples = 10
        lcs_length = 65
        time_to_build = "53.8 sec"
    strings:
        $s = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 
        40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
        00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 [-] 00 }
    condition:
        $s
}