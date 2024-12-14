import “hash”
rule ELPACO-team_Ransomware_Hash_Detection {
meta:
description = “To identify ELPACO-team ransomware hashes”
author = “CRT”
date = “15-11-2024”
condition:
hash.md5(0, filesize) == “33eeeb25f834e0b180f960ecb9518ea0” or
hash.md5(0, filesize) == “B93EB0A48C91A53BDA6A1A074A4B431E” or
hash.md5(0, filesize) == “AC34BA84A5054CD701EFAD5DD14645C9” or
hash.md5(0, filesize) == “0BF7C0D8E3E02A6B879EFAB5DEAB013C” or
hash.md5(0, filesize) == “C44487CE1827CE26AC4699432D15B42A” or
hash.md5(0, filesize) == “742C2400F2DE964D0CCE4A8DABADD708” or
hash.md5(0, filesize) == “51014C0C06ACDD80F9AE4469E7D30A9E” or
hash.md5(0, filesize) == “3B03324537327811BBBAFF4AAFA4D75B” or
hash.md5(0, filesize) == “245FB739C4CB3C944C11EF43CDDD8D57” or
hash.md5(0, filesize) == “1B37DC212E98A04576AAC40D7CE7D06A” or
hash.md5(0, filesize) == “26F59BB93F02D5A65538981BBC2DA9CC” or
hash.md5(0, filesize) == “03A63C096B9757439264B57E4FDF49D1” or
hash.md5(0, filesize) == “57850A4490A6AFD1EF682EB93EA45E65” or
hash.md5(0, filesize) == “FADE75EDBF62291FBB99C937AFC9792C” or
hash.md5(0, filesize) == “803DF907D936E08FBBD06020C411BE93” or
hash.md5(0, filesize) == “B951E50264F9C5244592DFB0A859EC41”
}