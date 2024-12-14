rule Backdoor_GHOSTSPIDER_beacon_loader
{
    strings:
        $clr = {
			C7 45 ?? 43 4C 52 43
			C7 45 ?? 72 65 61 74
			C7 45 ?? 65 49 6E 73
			C7 45 ?? 74 61 6E 63
		}

        $chunk1 = {
			C1 EA ??
			0F B6 D2
			8B 34 95 ?? ?? ?? ??
			8B 55 ??
			C1 EA ??
			8B 14 95 ?? ?? ?? ??
			C1 E9 ??
			0F B6 F9
			33 34 BD ?? ?? ?? ??
			8B 7D ??
			89 75 ??
			31 55 ??
			0F B6 55 ??
			8B 75 ??
			33 34 95 ?? ?? ?? ??
			8B D3
			33 B0 ?? ?? ?? ??
		}

        $chunk2 = {
            41 0F B6 1B
            41 8B C2
            99
            41 F7 F9
            48 63 C2
            0F B6 4C 05 ??
            44 03 C1
            44 03 C3
        }

    condition:
        uint16(0) == 0x5a4d and
		filesize < 300KB and
        (
            $clr and any of ($chunk*)
        )
}

rule Backdoor_GHOSTSPIDER_stager
{
    strings:
        $s1 = "new_comp" ascii wide
        $s2 = "del_comp" ascii wide
        $s3 = "new_client" ascii wide
        $s4 = "del_client" ascii wide
        $s5 = "new_base" ascii wide
        $s6 = "del_base" ascii wide
        $cookie = "phpsessid=%s; b=%d; path=/; expires=%s" ascii wide

    condition:
        uint16(0) == 0x5a4d and
        filesize < 300KB and
        (
            $cookie and 2 of ($s*)
        )
}