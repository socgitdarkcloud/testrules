rule Win32_Ransomware_CyberVolk : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "CYBERVOLK"
        description         = "Yara rule that detects CyberVolk ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "CyberVolk"
        tc_detection_factor = 5

    strings:

        $manage_gui_p1 = {
            55 8B EC 83 E4 ?? 81 EC ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 56 8B 35 ?? ?? ?? ?? 57 50
            6A ?? 6A ?? 6A ?? 6A ?? FF D6 8D 84 24 ?? ?? ?? ?? 50 8D 84 24 ?? ?? ?? ?? 68 ?? ??
            ?? ?? 50 E8 ?? ?? ?? ?? 8B 45 ?? 83 C4 ?? 3D ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 0F 84 ??
            ?? ?? ?? 83 F8 ?? 74 ?? 3D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 6A ?? FF
            D6 6A ?? 8B F8 FF D6 8B 75 ?? 99 2B C2 6A ?? D1 F8 68 ?? ?? ?? ?? 2D ?? ?? ?? ?? 68
            ?? ?? ?? ?? 50 8B C7 99 2B C2 D1 F8 2D ?? ?? ?? ?? 50 6A ?? 56 FF 15 ?? ?? ?? ?? 6A
            ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 8B E5 5D C2 ?? ??
            80 3D ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 6A ?? 6A ?? FF 75 ?? FF 15 ?? ?? ?? ?? 50 FF
            15 ?? ?? ?? ?? 89 44 24 ?? 8D 84 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B
            F0 83 C4 ?? BF ?? ?? ?? ?? 85 F6 74 ?? 56 8D 84 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8
            ?? ?? ?? ?? 83 C4 ?? 8D 84 24 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B F8 56 E8 ??
            ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 4F 50 FF 75 ?? 89 7C 24 ?? FF 15 ?? ?? ?? ?? 8B F8 57
            89 7C 24 ?? FF 15 ?? ?? ?? ?? FF 74 24 ?? 8B 35 ?? ?? ?? ?? 50 89 44 24 ?? FF D6 89
            44 24 ?? 8D 44 24 ?? 50 6A ?? FF 74 24 ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A
            ?? FF 74 24 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 57 FF 15 ?? ?? ?? ?? 68 ??
            ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 6A ?? 57 FF 15 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ??
            ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ??
            6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? FF 15 ??
            ?? ?? ?? 50 57 FF D6 8B 74 24 ?? B8 ?? ?? ?? ?? F7 EE B8 ?? ?? ?? ?? 03 D6 C1 FA ??
            8B FA C1 EF ?? 03 FA F7 EE 03 D6 C1 FA ?? 8B CA C1 E9 ?? 03 CA 8B D1 C1 E2 ?? 2B D1
        }

        $manage_gui_p2 = {
            C1 E2 ?? 8B CE B8 ?? ?? ?? ?? 2B CA 51 69 CF ?? ?? ?? ?? 2B F1 F7 EE 03 D6 C1 FA ??
            8B C2 C1 E8 ?? 03 C2 50 57 8D 84 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83
            C4 ?? 8D 44 24 ?? 6A ?? 50 6A ?? 8D 84 24 ?? ?? ?? ?? 50 FF 74 24 ?? FF 15 ?? ?? ??
            ?? FF 74 24 ?? 8B 74 24 ?? 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 8D 44 24 ?? 50
            FF 75 ?? FF 15 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B
            F0 83 C4 ?? 85 F6 0F 84 ?? ?? ?? ?? 8B 7C 24 ?? 8D 84 24 ?? ?? ?? ?? 57 68 ?? ?? ??
            ?? 50 E8 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 83 C4 ?? 8D 51 ?? 0F 1F 40 ?? 8A 01 41 84
            C0 75 ?? 56 2B CA 8D 84 24 ?? ?? ?? ?? 51 6A ?? 50 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ??
            83 C4 ?? 33 C0 5F 5E 8B E5 5D C2 ?? ?? 8B 3D ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? FF 75
            ?? FF D7 8B 35 ?? ?? ?? ?? 50 FF D6 8B 45 ?? 6A ?? 68 ?? ?? ?? ?? 50 FF D7 50 FF D6
            8B 75 ?? 6A ?? 6A ?? 56 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 89 44 24 ?? 8D 44 24
            ?? 50 56 FF 15 ?? ?? ?? ?? 50 89 44 24 ?? FF 15 ?? ?? ?? ?? FF 74 24 ?? 8B 3D ?? ??
            ?? ?? 50 89 44 24 ?? FF D7 8B F0 8D 44 24 ?? 50 6A ?? FF 74 24 ?? FF 15 ?? ?? ?? ??
            68 ?? ?? ?? ?? 6A ?? 6A ?? FF 74 24 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? FF
            74 24 ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 ?? FF 15 ?? ?? ?? ?? 6A ?? FF 74
            24 ?? FF 15 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24
            ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A
            ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 50 FF 74 24 ?? FF D7 6A
            ?? 8D 44 24 ?? 50 6A ?? 68 ?? ?? ?? ?? FF 74 24 ?? FF 15 ?? ?? ?? ?? 56 8B 74 24
        }

        $manage_gui_p3 = {
            56 FF D7 56 FF 15 ?? ?? ?? ?? 8D 44 24 ?? 50 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 33 C0 5F
            5E 8B E5 5D C2 ?? ?? 0F B7 45 ?? 3D ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 0F 84 ?? ?? ?? ??
            83 E8 ?? 0F 84 ?? ?? ?? ?? 2D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 8B 7D ?? 6A ?? 68 ?? ??
            ?? ?? 68 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 6A ?? 8D 44 24
            ?? C7 44 24 ?? ?? ?? ?? ?? 50 0F 57 C0 C6 44 24 ?? ?? 68 ?? ?? ?? ?? 57 0F 29 44 24
            ?? 0F 29 44 24 ?? FF 15 ?? ?? ?? ?? 8D 4C 24 ?? 8D 51 ?? 8A 01 41 84 C0 75 ?? 2B CA
            83 F9 ?? 74 ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? 33 C0 5F 5E 8B E5
            5D C2 ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? 50
            6A ?? 6A ?? 6A ?? 6A ?? FF D6 8D 84 24 ?? ?? ?? ?? 50 8D 84 24 ?? ?? ?? ?? 68 ?? ??
            ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 84 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ??
            ?? 8B F0 83 C4 ?? 85 F6 0F 84 ?? ?? ?? ?? 56 6A ?? 8D 44 24 ?? 6A ?? 50 E8 ?? ?? ??
            ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 5F 5E 8B E5 5D C2 ?? ?? 6A ?? FF 75 ?? FF 15 ??
            ?? ?? ?? B8 ?? ?? ?? ?? 5F 5E 8B E5 5D C2 ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F0
            56 FF 15 ?? ?? ?? ?? 0F 10 05 ?? ?? ?? ?? 0F 11 00 0F 10 05 ?? ?? ?? ?? 0F 11 40 ??
            F3 0F 7E 05 ?? ?? ?? ?? 66 0F D6 40 ?? 66 8B 0D ?? ?? ?? ?? 66 89 48 ?? 8A 0D ?? ??
            ?? ?? 88 48 ?? EB ?? 3D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ??
            8B F0 56 FF 15 ?? ?? ?? ?? 0F 10 05 ?? ?? ?? ?? 0F 11 00 0F 10 05 ?? ?? ?? ?? 0F 11
            40 ?? 66 8B 0D ?? ?? ?? ?? 66 89 48 ?? 8A 0D ?? ?? ?? ?? 88 48 ?? 56 FF 15 ?? ?? ??
            ?? 6A ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 56 6A ?? FF 15 ?? ?? ?? ?? FF 15 ?? ??
            ?? ?? 33 C0 5F 5E 8B E5 5D C2 ?? ?? 3D ?? ?? ?? ?? 75 ?? 81 7D
        }

        $find_files_v1_p1 = {
            55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 57 8B FA 8B D9 89 5D ?? 66 83 FF ?? 75
            ?? 80 3D ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50
            E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B CB 89 45 ?? 83 C4 ?? 66 A1 ?? ?? ?? ?? 66 89 45 ??
            8D 51 ?? 66 8B 01 83 C1 ?? 66 85 C0 75 ?? 2B CA D1 F9 81 F9 ?? ?? ?? ?? 0F 87 ?? ??
            ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 0F B7 0B 0F B7 95 ?? ??
            ?? ?? 8B D9 8B F2 8D 41 ?? 0F B7 C0 8D 4A ?? 89 45 ?? 66 83 F9 ?? 8D 46 ?? 0F B7 D0
            8B C6 8B 35 ?? ?? ?? ?? 0F 47 D0 66 83 7D ?? ?? 8D 43 ?? 0F B7 C8 8B C3 0F 47 C8 66
            3B D1 0F 85 ?? ?? ?? ?? 66 83 7D ?? ?? 8D 43 ?? 0F B7 C8 8B C3 8B 5D ?? 0F 47 C8 0F
            B7 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 66 89 0B 68 ?? ?? ?? ?? 50 FF
            D6 8D 8D ?? ?? ?? ?? 83 C4 ?? 8D 51 ?? 0F 1F 80 ?? ?? ?? ?? 66 8B 01 83 C1 ?? 66 85
            C0 75 ?? 2B CA 8D 85 ?? ?? ?? ?? D1 F9 51 50 53 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ??
            8B D7 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 53 FF 15 ?? ?? ?? ?? A8
            ?? 0F 85 ?? ?? ?? ?? EB ?? 8B 5D ?? 53 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF D6 83
            C4 ?? 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F0 89 75 ?? 83
            FE ?? 0F 84 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8D 51 ?? 0F 1F 80 ?? ?? ?? ?? 66 8B 01 83
            C1 ?? 66 85 C0 75 ?? 2B CA D1 F9 81 F9 ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 8B 85 ?? ?? ??
            ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? A8 ?? 0F 84 ?? ?? ??
            ?? 8D 4D ?? 8D 85 ?? ?? ?? ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66
            3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F
            84 ?? ?? ?? ?? 8D 4D ?? 8D 85 ?? ?? ?? ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66
        }

        $find_files_v1_p2 = {
            8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8
            ?? 85 C0 0F 84 ?? ?? ?? ?? 33 C0 53 66 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ??
            ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 68 ?? ?? ??
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8
            ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? 8B D7 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 53
            66 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D
            85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 85 ?? ?? ?? ?? 66 83
            FF ?? 75 ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ??
            51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? E8
            ?? ?? ?? ?? 83 C4 ?? EB ?? 66 83 FF ?? 75 ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8
            ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 83 EC ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ??
            ?? ?? ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? FF 15 ?? ?? ?? ?? 8D 85 ??
            ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 53 66 89 85 ?? ?? ?? ?? 8D
            85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 68 ?? ??
            ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 66 83 FF ?? 75 ?? 8D 85 ?? ?? ?? ??
            68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ?? 33 F6 66 66 0F 1F 84 00
            ?? ?? ?? ?? 80 BE ?? ?? ?? ?? ?? 8D 8E ?? ?? ?? ?? 74 ?? 57 6A ?? 6A ?? 51 E8 ?? ??
            ?? ?? 46 83 C4 ?? 81 FE ?? ?? ?? ?? 7C ?? 57 E8 ?? ?? ?? ?? 8B 75 ?? 83 C4 ?? 56 FF
            15 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3
        }

        $encrypt_files_v1_p1 = {
            53 8B DC 83 EC ?? 83 E4 ?? 83 C4 ?? 55 8B 6B ?? 89 6C 24 ?? 8B EC 6A ?? 68 ?? ?? ??
            ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 51 53 81 EC ?? ?? ?? ?? 53 56 57 89 65
            ?? 8B F9 89 7D ?? C7 45 ?? ?? ?? ?? ?? 0F 57 C0 0F 11 85 ?? ?? ?? ?? 0F 11 45 ?? C7
            45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 0F 13 45 ?? 66 0F 13
            45 ?? 66 0F 13 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ??
            68 ?? ?? ?? ?? 57 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 0F 8E ?? ?? ?? ??
            8B F7 8D 4E ?? 0F 1F 00 66 8B 06 83 C6 ?? 66 85 C0 75 ?? 2B F1 D1 FE 83 C6 ?? 89 75
            ?? C7 45 ?? ?? ?? ?? ?? 33 C9 8B C6 BA ?? ?? ?? ?? F7 E2 0F 90 C1 F7 D9 0B C8 51 E8
            ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 33 C9 66 89 08 57 56 50 E8 ?? ?? ?? ?? 83 C4 ?? 68 ??
            ?? ?? ?? 56 FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 56 8B 75 ?? 56 E8 ?? ??
            ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 56 8D 45 ?? 50 E8 ?? ?? ?? ?? 83
            C4 ?? 83 7D ?? ?? 0F 8E ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8B CA
            89 4D ?? 85 C9 0F 8C ?? ?? ?? ?? 7F ?? 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ??
            ?? ?? ?? 83 C4 ?? 8B F8 89 7D ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? BA ?? ?? ??
            ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 C4 ??
            6A ?? 8D 45 ?? 50 FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 57 FF 75 ?? E8 ??
            ?? ?? ?? 83 C4 ?? 8B C8 89 4D ?? 99 8B F0 89 75 ?? 89 55 ?? C7 45 ?? ?? ?? ?? ?? 81
        }

        $encrypt_files_v1_p2 = {
            F9 ?? ?? ?? ?? 7E ?? B9 ?? ?? ?? ?? 8B F7 8D BD ?? ?? ?? ?? F3 A5 8D 45 ?? 50 8D 45
            ?? 50 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ??
            ?? ?? ?? FF 75 ?? 8B 7D ?? 57 8B 75 ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? FF 75 ?? 8D 85 ??
            ?? ?? ?? 50 56 E8 ?? ?? ?? ?? 83 C4 ?? 8B 75 ?? 56 FF 75 ?? FF 75 ?? E8 ?? ?? ?? ??
            83 C4 ?? EB ?? 51 57 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 45 ?? 50 8D 45
            ?? 50 8D 85 ?? ?? ?? ?? 50 56 8D 95 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? FF
            75 ?? 8D 85 ?? ?? ?? ?? 50 FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 03 C6 89 45 ??
            8B 4D ?? 13 4D ?? 89 4D ?? 3B 4D ?? 0F 8C ?? ?? ?? ?? 7F ?? 3B 45 ?? 0F 82 ?? ?? ??
            ?? 6A ?? 68 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 6A ?? FF 75 ?? E8 ??
            ?? ?? ?? 83 C4 ?? E8 ?? ?? ?? ?? 8B F0 89 75 ?? 56 51 8D 85 ?? ?? ?? ?? 50 E8 ?? ??
            ?? ?? 83 C4 ?? 6A ?? 57 E8 ?? ?? ?? ?? 6A ?? 8B D7 8B CE E8 ?? ?? ?? ?? 83 C4 ?? 89
            45 ?? C7 45 ?? ?? ?? ?? ?? 8D 70 ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 56 8B D0 8B
            7D ?? 8B CF E8 ?? ?? ?? ?? 83 C4 ?? 56 8B 75 ?? 56 FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ??
            85 FF 74 ?? 8B CF E8 ?? ?? ?? ?? 8B 45 ?? 85 C0 74 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4
            ?? 6A ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 8B 7D ?? 8B 75 ?? 6A ?? 56 E8 ?? ?? ?? ?? 83 C4
            ?? 8B 45 ?? 85 C0 7E ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 85 C0 7E ?? 50 E8 ?? ??
            ?? ?? 83 C4 ?? 57 FF 15 ?? ?? ?? ?? 83 E0 ?? 50 57 FF 15 ?? ?? ?? ?? 57 FF 15 ?? ??
            ?? ?? B0 ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 5F 5E 5B 8B E5 5D 8B E3 5B C3
        }

        $find_files_v2_p1 = {
            55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 8B C2 8B D9 89 45 ?? 89 5D ?? 56 57 66 83
            F8 ?? 75 ?? 80 3D ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ??
            6A ?? 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B CB 89 45 ?? 83 C4 ?? 66 A1 ?? ?? ?? ?? 66
            89 45 ?? 8D 51 ?? 66 0F 1F 44 00 ?? 66 8B 01 83 C1 ?? 66 85 C0 75 ?? 2B CA D1 F9 81
            F9 ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ??
            ?? 0F B7 85 ?? ?? ?? ?? 8B F0 8D 48 ?? 8D 46 ?? 66 83 F9 ?? 0F B7 D0 8B CE 8B C6 0F
            47 D0 0F B7 03 0F B7 FA 8B D0 83 C0 ?? 0F B7 D8 66 83 F8 ?? 8B C6 76 ?? 0F B7 F0 83
            FB ?? 8D 42 ?? 0F B7 C8 8B C2 0F 47 C8 66 3B F9 8B 3D ?? ?? ?? ?? 0F 85 ?? ?? ?? ??
            68 ?? ?? ?? ?? 56 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF D7 8B 5D ?? 83 C4 ?? 0F B7
            03 8B F0 8B C8 83 C1 ?? 66 83 F9 ?? 8D 46 ?? 0F B7 D0 8B C6 0F 47 D0 0F B7 85 ?? ??
            ?? ?? 8B C8 66 89 13 8D 50 ?? 8D 41 ?? 66 83 FA ?? 0F B7 F0 8B C1 8B CB 0F 47 F0 66
            89 B5 ?? ?? ?? ?? 8D 51 ?? 0F 1F 00 66 8B 01 83 C1 ?? 66 85 C0 75 ?? 2B CA D1 F9 83
            F9 ?? 76 ?? 8D 85 ?? ?? ?? ?? 50 53 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ??
            EB ?? 8B 5D ?? 53 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF D7 83 C4 ?? 8D 85 ?? ?? ??
            ?? 50 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 8B
            8D ?? ?? ?? ?? 8D 41 ?? 66 83 F8 ?? 77 ?? 8D 41 ?? 0F B7 F8 EB ?? 0F B7 F9 0F B7 03
        }

        $find_files_v2_p2 = {
            8B F0 8B C8 83 C1 ?? 66 83 F9 ?? 8D 46 ?? 0F B7 D0 8B C6 0F 47 D0 66 3B FA 8B 95 ??
            ?? ?? ?? 75 ?? 83 FA ?? 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 70 ?? 66 8B 08 83 C0
            ?? 66 85 C9 75 ?? 2B C6 D1 F8 3D ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 83 FA ?? 0F 84 ?? ??
            ?? ?? 81 FA ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? F6 C2 ?? 0F 84 ?? ?? ?? ?? 8D 4D ?? 8D 85
            ?? ?? ?? ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83
            C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D
            4D ?? 8D 85 ?? ?? ?? ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51
            ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ??
            ?? ?? ?? 33 C0 53 66 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ??
            ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ??
            ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 55
            ?? 8D 8D ?? ?? ?? ?? 83 C4 ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 53 66 89 85 ?? ??
            ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ??
            50 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 45 ?? 83 C4 ?? 66 83 F8
        }

        $find_files_v2_p3 = {
            75 ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 85 ?? ??
            ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 51 8D
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? E8 ?? ??
            ?? ?? 83 C4 ?? EB ?? 66 83 F8 ?? 75 ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ??
            ?? ?? 83 C4 ?? 85 C0 74 ?? 83 EC ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ??
            ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? FF 15 ?? ?? ?? ?? 8D 85 ?? ?? ??
            ?? 50 FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 53 66 89 85 ?? ?? ?? ?? 8D
            85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 68 ?? ??
            ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 45 ?? 83 C4 ?? 66 83 F8 ?? 75 ?? 8D 85 ??
            ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ?? 33 F6 0F 1F 00
            80 BE ?? ?? ?? ?? ?? 8D 8E ?? ?? ?? ?? 74 ?? 57 6A ?? 6A ?? 51 E8 ?? ?? ?? ?? 46 83
            C4 ?? 81 FE ?? ?? ?? ?? 7C ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? FF 75 ?? FF 15 ?? ?? ?? ??
            5F 5E 5B 8B E5 5D C3
        }

        $encrypt_files_v2_p1 = {
            53 8B DC 83 EC ?? 83 E4 ?? 83 C4 ?? 55 8B 6B ?? 89 6C 24 ?? 8B EC 6A ?? 68 ?? ?? ??
            ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 51 53 81 EC ?? ?? ?? ?? 53 56 57 89 65
            ?? 8B F1 89 75 ?? C7 45 ?? ?? ?? ?? ?? 0F 57 C0 0F 11 85 ?? ?? ?? ?? 0F 11 45 ?? C7
            45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 0F 13 45 ?? 66 0F 13
            45 ?? 66 0F 13 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 56 68 ?? ?? ?? ?? E8
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 56 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4
            ?? FF 15 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 0F 8E ??
            ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 4E ?? 0F 1F 80 ?? ?? ?? ??
            66 8B 06 83 C6 ?? 66 85 C0 75 ?? 2B F1 D1 FE 83 C6 ?? 89 75 ?? C7 45 ?? ?? ?? ?? ??
            33 C9 8B C6 BA ?? ?? ?? ?? F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B
            F8 89 7D ?? 33 C0 66 89 07 FF 75 ?? 56 57 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 56
            57 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 56 57 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ??
            ?? 6A ?? 68 ?? ?? ?? ?? 57 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 0F 8E ??
            ?? ?? ?? 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ??
            8B CA 89 4D ?? 85 C9 0F 8C ?? ?? ?? ?? 7F ?? 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ??
            E8 ?? ?? ?? ?? 83 C4 ?? 8B F8 89 7D ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? BA ??
            ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 83
            C4 ?? 6A ?? 8D 45 ?? 50 FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? FF 75 ?? 68 ?? ?? ?? ?? E8
            ?? ?? ?? ?? 83 C4 ?? 90 68 ?? ?? ?? ?? 57 FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B C8 89
        }

        $encrypt_files_v2_p2 = {
            4D ?? 99 8B F0 89 75 ?? 89 55 ?? C7 45 ?? ?? ?? ?? ?? 81 F9 ?? ?? ?? ?? 7E ?? B9 ??
            ?? ?? ?? 8B F7 8D BD ?? ?? ?? ?? F3 A5 8D 45 ?? 50 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50
            68 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 75 ?? 8B 7D ??
            57 8B 75 ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? FF 75 ?? 8D 85 ?? ?? ?? ?? 50 56 E8 ?? ?? ??
            ?? 83 C4 ?? 8B 75 ?? 56 FF 75 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 51 57 8D 85
            ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 45 ?? 50 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50
            56 8D 95 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 75 ?? 8D 85 ?? ?? ?? ?? 50
            FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 03 C6 89 45 ?? 8B 4D ?? 13 4D ?? 89 4D ??
            3B 4D ?? 0F 8C ?? ?? ?? ?? 7F ?? 3B 45 ?? 0F 82 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? FF
            75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 6A ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? E8 ?? ??
            ?? ?? 8B F0 89 75 ?? 56 51 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 57 E8
            ?? ?? ?? ?? 6A ?? 8B D7 8B CE E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? C7 45 ?? ?? ?? ?? ??
            8D 70 ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 56 8B D0 8B 7D ?? 8B CF E8 ?? ?? ?? ??
            83 C4 ?? 56 8B 75 ?? 56 FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 FF 74 ?? 8B CF E8 ?? ??
            ?? ?? 8B 45 ?? 85 C0 74 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 56 E8 ?? ?? ?? ??
            83 C4 ?? 8B 7D ?? 6A ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 85 C0 7E ?? 50 E8 ?? ??
            ?? ?? 83 C4 ?? 8B 75 ?? 8B 45 ?? 85 C0 7E ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 56 E8 ?? ??
            ?? ?? 83 C4 ?? B0 ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 5F 5E 5B 8B E5 5D 8B E3 5B C3
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($manage_gui_p*)
        ) and
        (
            (
                (
                    all of ($find_files_v1_p*)
                ) and
                (
                    all of ($encrypt_files_v1_p*)
                )
            ) or
            (
                (
                    all of ($find_files_v2_p*)
                ) and
                (
                    all of ($encrypt_files_v2_p*)
                )
            )
        )
}