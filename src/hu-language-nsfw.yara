rule content_hu_language_nsfw_1 {
  meta:
    info = "balfasz"
  strings:
    $utf8 = "\x62\x61\x6c\x66\x61\x73\x7a" nocase fullword
    $wide = "\x62\x00\x61\x00\x6c\x00\x66\x00\x61\x00\x73\x00\x7a\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_2 {
  meta:
    info = "balfaszok"
  strings:
    $utf8 = "\x62\x61\x6c\x66\x61\x73\x7a\x6f\x6b" nocase fullword
    $wide = "\x62\x00\x61\x00\x6c\x00\x66\x00\x61\x00\x73\x00\x7a\x00\x6f\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_3 {
  meta:
    info = "balfaszokat"
  strings:
    $utf8 = "\x62\x61\x6c\x66\x61\x73\x7a\x6f\x6b\x61\x74" nocase fullword
    $wide = "\x62\x00\x61\x00\x6c\x00\x66\x00\x61\x00\x73\x00\x7a\x00\x6f\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_4 {
  meta:
    info = "balfaszt"
  strings:
    $utf8 = "\x62\x61\x6c\x66\x61\x73\x7a\x74" nocase fullword
    $wide = "\x62\x00\x61\x00\x6c\x00\x66\x00\x61\x00\x73\x00\x7a\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_5 {
  meta:
    info = "barmok"
  strings:
    $utf8 = "\x62\x61\x72\x6d\x6f\x6b" nocase fullword
    $wide = "\x62\x00\x61\x00\x72\x00\x6d\x00\x6f\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_6 {
  meta:
    info = "barmokat"
  strings:
    $utf8 = "\x62\x61\x72\x6d\x6f\x6b\x61\x74" nocase fullword
    $wide = "\x62\x00\x61\x00\x72\x00\x6d\x00\x6f\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_7 {
  meta:
    info = "barmot"
  strings:
    $utf8 = "\x62\x61\x72\x6d\x6f\x74" nocase fullword
    $wide = "\x62\x00\x61\x00\x72\x00\x6d\x00\x6f\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_8 {
  meta:
    info = "barom"
  strings:
    $utf8 = "\x62\x61\x72\x6f\x6d" nocase fullword
    $wide = "\x62\x00\x61\x00\x72\x00\x6f\x00\x6d\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_9 {
  meta:
    info = "baszik"
  strings:
    $utf8 = "\x62\x61\x73\x7a\x69\x6b" nocase fullword
    $wide = "\x62\x00\x61\x00\x73\x00\x7a\x00\x69\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_10 {
  meta:
    info = "bazmeg"
  strings:
    $utf8 = "\x62\x61\x7a\x6d\x65\x67" nocase fullword
    $wide = "\x62\x00\x61\x00\x7a\x00\x6d\x00\x65\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_11 {
  meta:
    info = "buksza"
  strings:
    $utf8 = "\x62\x75\x6b\x73\x7a\x61" nocase fullword
    $wide = "\x62\x00\x75\x00\x6b\x00\x73\x00\x7a\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_12 {
  meta:
    info = "bukszák"
  strings:
    $utf8 = "\x62\x75\x6b\x73\x7a\xc3\xa1\x6b" nocase fullword
    $wide = "\x62\x00\x75\x00\x6b\x00\x73\x00\x7a\x00\xe1\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_13 {
  meta:
    info = "bukszákat"
  strings:
    $utf8 = "\x62\x75\x6b\x73\x7a\xc3\xa1\x6b\x61\x74" nocase fullword
    $wide = "\x62\x00\x75\x00\x6b\x00\x73\x00\x7a\x00\xe1\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_14 {
  meta:
    info = "bukszát"
  strings:
    $utf8 = "\x62\x75\x6b\x73\x7a\xc3\xa1\x74" nocase fullword
    $wide = "\x62\x00\x75\x00\x6b\x00\x73\x00\x7a\x00\xe1\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_15 {
  meta:
    info = "búr"
  strings:
    $utf8 = "\x62\xc3\xba\x72" nocase fullword
    $wide = "\x62\x00\xfa\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_16 {
  meta:
    info = "búrok"
  strings:
    $utf8 = "\x62\xc3\xba\x72\x6f\x6b" nocase fullword
    $wide = "\x62\x00\xfa\x00\x72\x00\x6f\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_17 {
  meta:
    info = "csöcs"
  strings:
    $utf8 = "\x63\x73\xc3\xb6\x63\x73" nocase fullword
    $wide = "\x63\x00\x73\x00\xf6\x00\x63\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_18 {
  meta:
    info = "csöcsök"
  strings:
    $utf8 = "\x63\x73\xc3\xb6\x63\x73\xc3\xb6\x6b" nocase fullword
    $wide = "\x63\x00\x73\x00\xf6\x00\x63\x00\x73\x00\xf6\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_19 {
  meta:
    info = "csöcsöket"
  strings:
    $utf8 = "\x63\x73\xc3\xb6\x63\x73\xc3\xb6\x6b\x65\x74" nocase fullword
    $wide = "\x63\x00\x73\x00\xf6\x00\x63\x00\x73\x00\xf6\x00\x6b\x00\x65\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_20 {
  meta:
    info = "csöcsöt"
  strings:
    $utf8 = "\x63\x73\xc3\xb6\x63\x73\xc3\xb6\x74" nocase fullword
    $wide = "\x63\x00\x73\x00\xf6\x00\x63\x00\x73\x00\xf6\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_21 {
  meta:
    info = "fasz"
  strings:
    $utf8 = "\x66\x61\x73\x7a" nocase fullword
    $wide = "\x66\x00\x61\x00\x73\x00\x7a\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_22 {
  meta:
    info = "faszfej"
  strings:
    $utf8 = "\x66\x61\x73\x7a\x66\x65\x6a" nocase fullword
    $wide = "\x66\x00\x61\x00\x73\x00\x7a\x00\x66\x00\x65\x00\x6a\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_23 {
  meta:
    info = "faszfejek"
  strings:
    $utf8 = "\x66\x61\x73\x7a\x66\x65\x6a\x65\x6b" nocase fullword
    $wide = "\x66\x00\x61\x00\x73\x00\x7a\x00\x66\x00\x65\x00\x6a\x00\x65\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_24 {
  meta:
    info = "faszfejeket"
  strings:
    $utf8 = "\x66\x61\x73\x7a\x66\x65\x6a\x65\x6b\x65\x74" nocase fullword
    $wide = "\x66\x00\x61\x00\x73\x00\x7a\x00\x66\x00\x65\x00\x6a\x00\x65\x00\x6b\x00\x65\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_25 {
  meta:
    info = "faszfejet"
  strings:
    $utf8 = "\x66\x61\x73\x7a\x66\x65\x6a\x65\x74" nocase fullword
    $wide = "\x66\x00\x61\x00\x73\x00\x7a\x00\x66\x00\x65\x00\x6a\x00\x65\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_26 {
  meta:
    info = "faszok"
  strings:
    $utf8 = "\x66\x61\x73\x7a\x6f\x6b" nocase fullword
    $wide = "\x66\x00\x61\x00\x73\x00\x7a\x00\x6f\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_27 {
  meta:
    info = "faszokat"
  strings:
    $utf8 = "\x66\x61\x73\x7a\x6f\x6b\x61\x74" nocase fullword
    $wide = "\x66\x00\x61\x00\x73\x00\x7a\x00\x6f\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_28 {
  meta:
    info = "faszt"
  strings:
    $utf8 = "\x66\x61\x73\x7a\x74" nocase fullword
    $wide = "\x66\x00\x61\x00\x73\x00\x7a\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_30 {
  meta:
    info = "fingok"
  strings:
    $utf8 = "\x66\x69\x6e\x67\x6f\x6b" nocase fullword
    $wide = "\x66\x00\x69\x00\x6e\x00\x67\x00\x6f\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_31 {
  meta:
    info = "fingokat"
  strings:
    $utf8 = "\x66\x69\x6e\x67\x6f\x6b\x61\x74" nocase fullword
    $wide = "\x66\x00\x69\x00\x6e\x00\x67\x00\x6f\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_32 {
  meta:
    info = "fingot"
  strings:
    $utf8 = "\x66\x69\x6e\x67\x6f\x74" nocase fullword
    $wide = "\x66\x00\x69\x00\x6e\x00\x67\x00\x6f\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_33 {
  meta:
    info = "franc"
  strings:
    $utf8 = "\x66\x72\x61\x6e\x63" nocase fullword
    $wide = "\x66\x00\x72\x00\x61\x00\x6e\x00\x63\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_34 {
  meta:
    info = "francok"
  strings:
    $utf8 = "\x66\x72\x61\x6e\x63\x6f\x6b" nocase fullword
    $wide = "\x66\x00\x72\x00\x61\x00\x6e\x00\x63\x00\x6f\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_35 {
  meta:
    info = "francokat"
  strings:
    $utf8 = "\x66\x72\x61\x6e\x63\x6f\x6b\x61\x74" nocase fullword
    $wide = "\x66\x00\x72\x00\x61\x00\x6e\x00\x63\x00\x6f\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_36 {
  meta:
    info = "francot"
  strings:
    $utf8 = "\x66\x72\x61\x6e\x63\x6f\x74" nocase fullword
    $wide = "\x66\x00\x72\x00\x61\x00\x6e\x00\x63\x00\x6f\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_37 {
  meta:
    info = "geci"
  strings:
    $utf8 = "\x67\x65\x63\x69" nocase fullword
    $wide = "\x67\x00\x65\x00\x63\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_38 {
  meta:
    info = "gecibb"
  strings:
    $utf8 = "\x67\x65\x63\x69\x62\x62" nocase fullword
    $wide = "\x67\x00\x65\x00\x63\x00\x69\x00\x62\x00\x62\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_39 {
  meta:
    info = "gecik"
  strings:
    $utf8 = "\x67\x65\x63\x69\x6b" nocase fullword
    $wide = "\x67\x00\x65\x00\x63\x00\x69\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_40 {
  meta:
    info = "geciket"
  strings:
    $utf8 = "\x67\x65\x63\x69\x6b\x65\x74" nocase fullword
    $wide = "\x67\x00\x65\x00\x63\x00\x69\x00\x6b\x00\x65\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_41 {
  meta:
    info = "gecit"
  strings:
    $utf8 = "\x67\x65\x63\x69\x74" nocase fullword
    $wide = "\x67\x00\x65\x00\x63\x00\x69\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_42 {
  meta:
    info = "kibaszott"
  strings:
    $utf8 = "\x6b\x69\x62\x61\x73\x7a\x6f\x74\x74" nocase fullword
    $wide = "\x6b\x00\x69\x00\x62\x00\x61\x00\x73\x00\x7a\x00\x6f\x00\x74\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_43 {
  meta:
    info = "kibaszottabb"
  strings:
    $utf8 = "\x6b\x69\x62\x61\x73\x7a\x6f\x74\x74\x61\x62\x62" nocase fullword
    $wide = "\x6b\x00\x69\x00\x62\x00\x61\x00\x73\x00\x7a\x00\x6f\x00\x74\x00\x74\x00\x61\x00\x62\x00\x62\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_44 {
  meta:
    info = "kurafi"
  strings:
    $utf8 = "\x6b\x75\x72\x61\x66\x69" nocase fullword
    $wide = "\x6b\x00\x75\x00\x72\x00\x61\x00\x66\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_45 {
  meta:
    info = "kurafik"
  strings:
    $utf8 = "\x6b\x75\x72\x61\x66\x69\x6b" nocase fullword
    $wide = "\x6b\x00\x75\x00\x72\x00\x61\x00\x66\x00\x69\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_46 {
  meta:
    info = "kurafikat"
  strings:
    $utf8 = "\x6b\x75\x72\x61\x66\x69\x6b\x61\x74" nocase fullword
    $wide = "\x6b\x00\x75\x00\x72\x00\x61\x00\x66\x00\x69\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_47 {
  meta:
    info = "kurafit"
  strings:
    $utf8 = "\x6b\x75\x72\x61\x66\x69\x74" nocase fullword
    $wide = "\x6b\x00\x75\x00\x72\x00\x61\x00\x66\x00\x69\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_48 {
  meta:
    info = "kurva"
  strings:
    $utf8 = "\x6b\x75\x72\x76\x61" nocase fullword
    $wide = "\x6b\x00\x75\x00\x72\x00\x76\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_49 {
  meta:
    info = "kurvák"
  strings:
    $utf8 = "\x6b\x75\x72\x76\xc3\xa1\x6b" nocase fullword
    $wide = "\x6b\x00\x75\x00\x72\x00\x76\x00\xe1\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_50 {
  meta:
    info = "kurvákat"
  strings:
    $utf8 = "\x6b\x75\x72\x76\xc3\xa1\x6b\x61\x74" nocase fullword
    $wide = "\x6b\x00\x75\x00\x72\x00\x76\x00\xe1\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_51 {
  meta:
    info = "kurvát"
  strings:
    $utf8 = "\x6b\x75\x72\x76\xc3\xa1\x74" nocase fullword
    $wide = "\x6b\x00\x75\x00\x72\x00\x76\x00\xe1\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_52 {
  meta:
    info = "kúr"
  strings:
    $utf8 = "\x6b\xc3\xba\x72" nocase fullword
    $wide = "\x6b\x00\xfa\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_53 {
  meta:
    info = "leggecibb"
  strings:
    $utf8 = "\x6c\x65\x67\x67\x65\x63\x69\x62\x62" nocase fullword
    $wide = "\x6c\x00\x65\x00\x67\x00\x67\x00\x65\x00\x63\x00\x69\x00\x62\x00\x62\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_54 {
  meta:
    info = "legkibaszottabb"
  strings:
    $utf8 = "\x6c\x65\x67\x6b\x69\x62\x61\x73\x7a\x6f\x74\x74\x61\x62\x62" nocase fullword
    $wide = "\x6c\x00\x65\x00\x67\x00\x6b\x00\x69\x00\x62\x00\x61\x00\x73\x00\x7a\x00\x6f\x00\x74\x00\x74\x00\x61\x00\x62\x00\x62\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_55 {
  meta:
    info = "legszarabb"
  strings:
    $utf8 = "\x6c\x65\x67\x73\x7a\x61\x72\x61\x62\x62" nocase fullword
    $wide = "\x6c\x00\x65\x00\x67\x00\x73\x00\x7a\x00\x61\x00\x72\x00\x61\x00\x62\x00\x62\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_56 {
  meta:
    info = "marha"
  strings:
    $utf8 = "\x6d\x61\x72\x68\x61" nocase fullword
    $wide = "\x6d\x00\x61\x00\x72\x00\x68\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_57 {
  meta:
    info = "marhák"
  strings:
    $utf8 = "\x6d\x61\x72\x68\xc3\xa1\x6b" nocase fullword
    $wide = "\x6d\x00\x61\x00\x72\x00\x68\x00\xe1\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_58 {
  meta:
    info = "marhákat"
  strings:
    $utf8 = "\x6d\x61\x72\x68\xc3\xa1\x6b\x61\x74" nocase fullword
    $wide = "\x6d\x00\x61\x00\x72\x00\x68\x00\xe1\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_59 {
  meta:
    info = "marhát"
  strings:
    $utf8 = "\x6d\x61\x72\x68\xc3\xa1\x74" nocase fullword
    $wide = "\x6d\x00\x61\x00\x72\x00\x68\x00\xe1\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_60 {
  meta:
    info = "megdöglik"
  strings:
    $utf8 = "\x6d\x65\x67\x64\xc3\xb6\x67\x6c\x69\x6b" nocase fullword
    $wide = "\x6d\x00\x65\x00\x67\x00\x64\x00\xf6\x00\x67\x00\x6c\x00\x69\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_61 {
  meta:
    info = "pele"
  strings:
    $utf8 = "\x70\x65\x6c\x65" nocase fullword
    $wide = "\x70\x00\x65\x00\x6c\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_62 {
  meta:
    info = "pelék"
  strings:
    $utf8 = "\x70\x65\x6c\xc3\xa9\x6b" nocase fullword
    $wide = "\x70\x00\x65\x00\x6c\x00\xe9\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_63 {
  meta:
    info = "picsa"
  strings:
    $utf8 = "\x70\x69\x63\x73\x61" nocase fullword
    $wide = "\x70\x00\x69\x00\x63\x00\x73\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_64 {
  meta:
    info = "picsákat"
  strings:
    $utf8 = "\x70\x69\x63\x73\xc3\xa1\x6b\x61\x74" nocase fullword
    $wide = "\x70\x00\x69\x00\x63\x00\x73\x00\xe1\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_65 {
  meta:
    info = "picsát"
  strings:
    $utf8 = "\x70\x69\x63\x73\xc3\xa1\x74" nocase fullword
    $wide = "\x70\x00\x69\x00\x63\x00\x73\x00\xe1\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_66 {
  meta:
    info = "pina"
  strings:
    $utf8 = "\x70\x69\x6e\x61" nocase fullword
    $wide = "\x70\x00\x69\x00\x6e\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_67 {
  meta:
    info = "pinák"
  strings:
    $utf8 = "\x70\x69\x6e\xc3\xa1\x6b" nocase fullword
    $wide = "\x70\x00\x69\x00\x6e\x00\xe1\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_68 {
  meta:
    info = "pinákat"
  strings:
    $utf8 = "\x70\x69\x6e\xc3\xa1\x6b\x61\x74" nocase fullword
    $wide = "\x70\x00\x69\x00\x6e\x00\xe1\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_69 {
  meta:
    info = "pinát"
  strings:
    $utf8 = "\x70\x69\x6e\xc3\xa1\x74" nocase fullword
    $wide = "\x70\x00\x69\x00\x6e\x00\xe1\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_71 {
  meta:
    info = "pofákat"
  strings:
    $utf8 = "\x70\x6f\x66\xc3\xa1\x6b\x61\x74" nocase fullword
    $wide = "\x70\x00\x6f\x00\x66\x00\xe1\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_72 {
  meta:
    info = "pofát"
  strings:
    $utf8 = "\x70\x6f\x66\xc3\xa1\x74" nocase fullword
    $wide = "\x70\x00\x6f\x00\x66\x00\xe1\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_73 {
  meta:
    info = "punci"
  strings:
    $utf8 = "\x70\x75\x6e\x63\x69" nocase fullword
    $wide = "\x70\x00\x75\x00\x6e\x00\x63\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_74 {
  meta:
    info = "puncik"
  strings:
    $utf8 = "\x70\x75\x6e\x63\x69\x6b" nocase fullword
    $wide = "\x70\x00\x75\x00\x6e\x00\x63\x00\x69\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_75 {
  meta:
    info = "pöcs"
  strings:
    $utf8 = "\x70\xc3\xb6\x63\x73" nocase fullword
    $wide = "\x70\x00\xf6\x00\x63\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_76 {
  meta:
    info = "pöcsök"
  strings:
    $utf8 = "\x70\xc3\xb6\x63\x73\xc3\xb6\x6b" nocase fullword
    $wide = "\x70\x00\xf6\x00\x63\x00\x73\x00\xf6\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_77 {
  meta:
    info = "pöcsöket"
  strings:
    $utf8 = "\x70\xc3\xb6\x63\x73\xc3\xb6\x6b\x65\x74" nocase fullword
    $wide = "\x70\x00\xf6\x00\x63\x00\x73\x00\xf6\x00\x6b\x00\x65\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_78 {
  meta:
    info = "pöcsöt"
  strings:
    $utf8 = "\x70\xc3\xb6\x63\x73\xc3\xb6\x74" nocase fullword
    $wide = "\x70\x00\xf6\x00\x63\x00\x73\x00\xf6\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_79 {
  meta:
    info = "segg"
  strings:
    $utf8 = "\x73\x65\x67\x67" nocase fullword
    $wide = "\x73\x00\x65\x00\x67\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_80 {
  meta:
    info = "seggek"
  strings:
    $utf8 = "\x73\x65\x67\x67\x65\x6b" nocase fullword
    $wide = "\x73\x00\x65\x00\x67\x00\x67\x00\x65\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_81 {
  meta:
    info = "seggeket"
  strings:
    $utf8 = "\x73\x65\x67\x67\x65\x6b\x65\x74" nocase fullword
    $wide = "\x73\x00\x65\x00\x67\x00\x67\x00\x65\x00\x6b\x00\x65\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_82 {
  meta:
    info = "segget"
  strings:
    $utf8 = "\x73\x65\x67\x67\x65\x74" nocase fullword
    $wide = "\x73\x00\x65\x00\x67\x00\x67\x00\x65\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_83 {
  meta:
    info = "seggfej"
  strings:
    $utf8 = "\x73\x65\x67\x67\x66\x65\x6a" nocase fullword
    $wide = "\x73\x00\x65\x00\x67\x00\x67\x00\x66\x00\x65\x00\x6a\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_84 {
  meta:
    info = "seggfejek"
  strings:
    $utf8 = "\x73\x65\x67\x67\x66\x65\x6a\x65\x6b" nocase fullword
    $wide = "\x73\x00\x65\x00\x67\x00\x67\x00\x66\x00\x65\x00\x6a\x00\x65\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_85 {
  meta:
    info = "seggfejeket"
  strings:
    $utf8 = "\x73\x65\x67\x67\x66\x65\x6a\x65\x6b\x65\x74" nocase fullword
    $wide = "\x73\x00\x65\x00\x67\x00\x67\x00\x66\x00\x65\x00\x6a\x00\x65\x00\x6b\x00\x65\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_86 {
  meta:
    info = "seggfejet"
  strings:
    $utf8 = "\x73\x65\x67\x67\x66\x65\x6a\x65\x74" nocase fullword
    $wide = "\x73\x00\x65\x00\x67\x00\x67\x00\x66\x00\x65\x00\x6a\x00\x65\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_87 {
  meta:
    info = "szajha"
  strings:
    $utf8 = "\x73\x7a\x61\x6a\x68\x61" nocase fullword
    $wide = "\x73\x00\x7a\x00\x61\x00\x6a\x00\x68\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_88 {
  meta:
    info = "szajhák"
  strings:
    $utf8 = "\x73\x7a\x61\x6a\x68\xc3\xa1\x6b" nocase fullword
    $wide = "\x73\x00\x7a\x00\x61\x00\x6a\x00\x68\x00\xe1\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_89 {
  meta:
    info = "szajhákat"
  strings:
    $utf8 = "\x73\x7a\x61\x6a\x68\xc3\xa1\x6b\x61\x74" nocase fullword
    $wide = "\x73\x00\x7a\x00\x61\x00\x6a\x00\x68\x00\xe1\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_90 {
  meta:
    info = "szajhát"
  strings:
    $utf8 = "\x73\x7a\x61\x6a\x68\xc3\xa1\x74" nocase fullword
    $wide = "\x73\x00\x7a\x00\x61\x00\x6a\x00\x68\x00\xe1\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_91 {
  meta:
    info = "szar"
  strings:
    $utf8 = "\x73\x7a\x61\x72" nocase fullword
    $wide = "\x73\x00\x7a\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_92 {
  meta:
    info = "szarabb"
  strings:
    $utf8 = "\x73\x7a\x61\x72\x61\x62\x62" nocase fullword
    $wide = "\x73\x00\x7a\x00\x61\x00\x72\x00\x61\x00\x62\x00\x62\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_93 {
  meta:
    info = "szarik"
  strings:
    $utf8 = "\x73\x7a\x61\x72\x69\x6b" nocase fullword
    $wide = "\x73\x00\x7a\x00\x61\x00\x72\x00\x69\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_94 {
  meta:
    info = "szarok"
  strings:
    $utf8 = "\x73\x7a\x61\x72\x6f\x6b" nocase fullword
    $wide = "\x73\x00\x7a\x00\x61\x00\x72\x00\x6f\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_95 {
  meta:
    info = "szarokat"
  strings:
    $utf8 = "\x73\x7a\x61\x72\x6f\x6b\x61\x74" nocase fullword
    $wide = "\x73\x00\x7a\x00\x61\x00\x72\x00\x6f\x00\x6b\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hu_language_nsfw_96 {
  meta:
    info = "szart"
  strings:
    $utf8 = "\x73\x7a\x61\x72\x74" nocase fullword
    $wide = "\x73\x00\x7a\x00\x61\x00\x72\x00\x74\x00" nocase fullword
  condition:
    any of them
}
