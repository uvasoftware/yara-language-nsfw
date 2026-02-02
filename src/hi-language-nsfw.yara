rule content_hi_language_nsfw_1 {
  meta:
    info = "aand"
  strings:
    $utf8 = "\x61\x61\x6e\x64" nocase fullword
    $wide = "\x61\x00\x61\x00\x6e\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_2 {
  meta:
    info = "aandu"
  strings:
    $utf8 = "\x61\x61\x6e\x64\x75" nocase fullword
    $wide = "\x61\x00\x61\x00\x6e\x00\x64\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_3 {
  meta:
    info = "balatkar"
  strings:
    $utf8 = "\x62\x61\x6c\x61\x74\x6b\x61\x72" nocase fullword
    $wide = "\x62\x00\x61\x00\x6c\x00\x61\x00\x74\x00\x6b\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_4 {
  meta:
    info = "beti chod"
  strings:
    $utf8 = "\x62\x65\x74\x69\x20\x63\x68\x6f\x64" nocase fullword
    $wide = "\x62\x00\x65\x00\x74\x00\x69\x00\x20\x00\x63\x00\x68\x00\x6f\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_5 {
  meta:
    info = "bhadva"
  strings:
    $utf8 = "\x62\x68\x61\x64\x76\x61" nocase fullword
    $wide = "\x62\x00\x68\x00\x61\x00\x64\x00\x76\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_6 {
  meta:
    info = "bhadve"
  strings:
    $utf8 = "\x62\x68\x61\x64\x76\x65" nocase fullword
    $wide = "\x62\x00\x68\x00\x61\x00\x64\x00\x76\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_7 {
  meta:
    info = "bhandve"
  strings:
    $utf8 = "\x62\x68\x61\x6e\x64\x76\x65" nocase fullword
    $wide = "\x62\x00\x68\x00\x61\x00\x6e\x00\x64\x00\x76\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_8 {
  meta:
    info = "bhootni ke"
  strings:
    $utf8 = "\x62\x68\x6f\x6f\x74\x6e\x69\x20\x6b\x65" nocase fullword
    $wide = "\x62\x00\x68\x00\x6f\x00\x6f\x00\x74\x00\x6e\x00\x69\x00\x20\x00\x6b\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_9 {
  meta:
    info = "bhosad"
  strings:
    $utf8 = "\x62\x68\x6f\x73\x61\x64" nocase fullword
    $wide = "\x62\x00\x68\x00\x6f\x00\x73\x00\x61\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_10 {
  meta:
    info = "bhosadi ke"
  strings:
    $utf8 = "\x62\x68\x6f\x73\x61\x64\x69\x20\x6b\x65" nocase fullword
    $wide = "\x62\x00\x68\x00\x6f\x00\x73\x00\x61\x00\x64\x00\x69\x00\x20\x00\x6b\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_11 {
  meta:
    info = "boobe"
  strings:
    $utf8 = "\x62\x6f\x6f\x62\x65" nocase fullword
    $wide = "\x62\x00\x6f\x00\x6f\x00\x62\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_12 {
  meta:
    info = "chakke"
  strings:
    $utf8 = "\x63\x68\x61\x6b\x6b\x65" nocase fullword
    $wide = "\x63\x00\x68\x00\x61\x00\x6b\x00\x6b\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_13 {
  meta:
    info = "chinaal"
  strings:
    $utf8 = "\x63\x68\x69\x6e\x61\x61\x6c" nocase fullword
    $wide = "\x63\x00\x68\x00\x69\x00\x6e\x00\x61\x00\x61\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_14 {
  meta:
    info = "chinki"
  strings:
    $utf8 = "\x63\x68\x69\x6e\x6b\x69" nocase fullword
    $wide = "\x63\x00\x68\x00\x69\x00\x6e\x00\x6b\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_15 {
  meta:
    info = "chod"
  strings:
    $utf8 = "\x63\x68\x6f\x64" nocase fullword
    $wide = "\x63\x00\x68\x00\x6f\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_16 {
  meta:
    info = "chodu"
  strings:
    $utf8 = "\x63\x68\x6f\x64\x75" nocase fullword
    $wide = "\x63\x00\x68\x00\x6f\x00\x64\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_17 {
  meta:
    info = "chodu bhagat"
  strings:
    $utf8 = "\x63\x68\x6f\x64\x75\x20\x62\x68\x61\x67\x61\x74" nocase fullword
    $wide = "\x63\x00\x68\x00\x6f\x00\x64\x00\x75\x00\x20\x00\x62\x00\x68\x00\x61\x00\x67\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_18 {
  meta:
    info = "chooche"
  strings:
    $utf8 = "\x63\x68\x6f\x6f\x63\x68\x65" nocase fullword
    $wide = "\x63\x00\x68\x00\x6f\x00\x6f\x00\x63\x00\x68\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_19 {
  meta:
    info = "choochi"
  strings:
    $utf8 = "\x63\x68\x6f\x6f\x63\x68\x69" nocase fullword
    $wide = "\x63\x00\x68\x00\x6f\x00\x6f\x00\x63\x00\x68\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_20 {
  meta:
    info = "choot"
  strings:
    $utf8 = "\x63\x68\x6f\x6f\x74" nocase fullword
    $wide = "\x63\x00\x68\x00\x6f\x00\x6f\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_21 {
  meta:
    info = "choot ke baal"
  strings:
    $utf8 = "\x63\x68\x6f\x6f\x74\x20\x6b\x65\x20\x62\x61\x61\x6c" nocase fullword
    $wide = "\x63\x00\x68\x00\x6f\x00\x6f\x00\x74\x00\x20\x00\x6b\x00\x65\x00\x20\x00\x62\x00\x61\x00\x61\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_22 {
  meta:
    info = "chootia"
  strings:
    $utf8 = "\x63\x68\x6f\x6f\x74\x69\x61" nocase fullword
    $wide = "\x63\x00\x68\x00\x6f\x00\x6f\x00\x74\x00\x69\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_23 {
  meta:
    info = "chootiya"
  strings:
    $utf8 = "\x63\x68\x6f\x6f\x74\x69\x79\x61" nocase fullword
    $wide = "\x63\x00\x68\x00\x6f\x00\x6f\x00\x74\x00\x69\x00\x79\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_24 {
  meta:
    info = "chuche"
  strings:
    $utf8 = "\x63\x68\x75\x63\x68\x65" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x63\x00\x68\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_25 {
  meta:
    info = "chuchi"
  strings:
    $utf8 = "\x63\x68\x75\x63\x68\x69" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x63\x00\x68\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_26 {
  meta:
    info = "chudai khanaa"
  strings:
    $utf8 = "\x63\x68\x75\x64\x61\x69\x20\x6b\x68\x61\x6e\x61\x61" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x64\x00\x61\x00\x69\x00\x20\x00\x6b\x00\x68\x00\x61\x00\x6e\x00\x61\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_27 {
  meta:
    info = "chudan chudai"
  strings:
    $utf8 = "\x63\x68\x75\x64\x61\x6e\x20\x63\x68\x75\x64\x61\x69" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x64\x00\x61\x00\x6e\x00\x20\x00\x63\x00\x68\x00\x75\x00\x64\x00\x61\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_28 {
  meta:
    info = "chut"
  strings:
    $utf8 = "\x63\x68\x75\x74" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_29 {
  meta:
    info = "chut ke baal"
  strings:
    $utf8 = "\x63\x68\x75\x74\x20\x6b\x65\x20\x62\x61\x61\x6c" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x74\x00\x20\x00\x6b\x00\x65\x00\x20\x00\x62\x00\x61\x00\x61\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_30 {
  meta:
    info = "chut ke dhakkan"
  strings:
    $utf8 = "\x63\x68\x75\x74\x20\x6b\x65\x20\x64\x68\x61\x6b\x6b\x61\x6e" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x74\x00\x20\x00\x6b\x00\x65\x00\x20\x00\x64\x00\x68\x00\x61\x00\x6b\x00\x6b\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_31 {
  meta:
    info = "chut maarli"
  strings:
    $utf8 = "\x63\x68\x75\x74\x20\x6d\x61\x61\x72\x6c\x69" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x74\x00\x20\x00\x6d\x00\x61\x00\x61\x00\x72\x00\x6c\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_32 {
  meta:
    info = "chutad"
  strings:
    $utf8 = "\x63\x68\x75\x74\x61\x64" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x74\x00\x61\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_33 {
  meta:
    info = "chutadd"
  strings:
    $utf8 = "\x63\x68\x75\x74\x61\x64\x64" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x74\x00\x61\x00\x64\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_34 {
  meta:
    info = "chutan"
  strings:
    $utf8 = "\x63\x68\x75\x74\x61\x6e" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x74\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_35 {
  meta:
    info = "chutia"
  strings:
    $utf8 = "\x63\x68\x75\x74\x69\x61" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x74\x00\x69\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_36 {
  meta:
    info = "chutiya"
  strings:
    $utf8 = "\x63\x68\x75\x74\x69\x79\x61" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x74\x00\x69\x00\x79\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_38 {
  meta:
    info = "gaandfat"
  strings:
    $utf8 = "\x67\x61\x61\x6e\x64\x66\x61\x74" nocase fullword
    $wide = "\x67\x00\x61\x00\x61\x00\x6e\x00\x64\x00\x66\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_39 {
  meta:
    info = "gaandmasti"
  strings:
    $utf8 = "\x67\x61\x61\x6e\x64\x6d\x61\x73\x74\x69" nocase fullword
    $wide = "\x67\x00\x61\x00\x61\x00\x6e\x00\x64\x00\x6d\x00\x61\x00\x73\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_40 {
  meta:
    info = "gaandufad"
  strings:
    $utf8 = "\x67\x61\x61\x6e\x64\x75\x66\x61\x64" nocase fullword
    $wide = "\x67\x00\x61\x00\x61\x00\x6e\x00\x64\x00\x75\x00\x66\x00\x61\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_41 {
  meta:
    info = "gandu"
  strings:
    $utf8 = "\x67\x61\x6e\x64\x75" nocase fullword
    $wide = "\x67\x00\x61\x00\x6e\x00\x64\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_42 {
  meta:
    info = "gashti"
  strings:
    $utf8 = "\x67\x61\x73\x68\x74\x69" nocase fullword
    $wide = "\x67\x00\x61\x00\x73\x00\x68\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_43 {
  meta:
    info = "gasti"
  strings:
    $utf8 = "\x67\x61\x73\x74\x69" nocase fullword
    $wide = "\x67\x00\x61\x00\x73\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_44 {
  meta:
    info = "ghassa"
  strings:
    $utf8 = "\x67\x68\x61\x73\x73\x61" nocase fullword
    $wide = "\x67\x00\x68\x00\x61\x00\x73\x00\x73\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_45 {
  meta:
    info = "ghasti"
  strings:
    $utf8 = "\x67\x68\x61\x73\x74\x69" nocase fullword
    $wide = "\x67\x00\x68\x00\x61\x00\x73\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_47 {
  meta:
    info = "haramzade"
  strings:
    $utf8 = "\x68\x61\x72\x61\x6d\x7a\x61\x64\x65" nocase fullword
    $wide = "\x68\x00\x61\x00\x72\x00\x61\x00\x6d\x00\x7a\x00\x61\x00\x64\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_48 {
  meta:
    info = "hawas"
  strings:
    $utf8 = "\x68\x61\x77\x61\x73" nocase fullword
    $wide = "\x68\x00\x61\x00\x77\x00\x61\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_49 {
  meta:
    info = "hawas ke pujari"
  strings:
    $utf8 = "\x68\x61\x77\x61\x73\x20\x6b\x65\x20\x70\x75\x6a\x61\x72\x69" nocase fullword
    $wide = "\x68\x00\x61\x00\x77\x00\x61\x00\x73\x00\x20\x00\x6b\x00\x65\x00\x20\x00\x70\x00\x75\x00\x6a\x00\x61\x00\x72\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_50 {
  meta:
    info = "hijda"
  strings:
    $utf8 = "\x68\x69\x6a\x64\x61" nocase fullword
    $wide = "\x68\x00\x69\x00\x6a\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_51 {
  meta:
    info = "hijra"
  strings:
    $utf8 = "\x68\x69\x6a\x72\x61" nocase fullword
    $wide = "\x68\x00\x69\x00\x6a\x00\x72\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_53 {
  meta:
    info = "jhant chaatu"
  strings:
    $utf8 = "\x6a\x68\x61\x6e\x74\x20\x63\x68\x61\x61\x74\x75" nocase fullword
    $wide = "\x6a\x00\x68\x00\x61\x00\x6e\x00\x74\x00\x20\x00\x63\x00\x68\x00\x61\x00\x61\x00\x74\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_54 {
  meta:
    info = "jhant ke baal"
  strings:
    $utf8 = "\x6a\x68\x61\x6e\x74\x20\x6b\x65\x20\x62\x61\x61\x6c" nocase fullword
    $wide = "\x6a\x00\x68\x00\x61\x00\x6e\x00\x74\x00\x20\x00\x6b\x00\x65\x00\x20\x00\x62\x00\x61\x00\x61\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_55 {
  meta:
    info = "jhantu"
  strings:
    $utf8 = "\x6a\x68\x61\x6e\x74\x75" nocase fullword
    $wide = "\x6a\x00\x68\x00\x61\x00\x6e\x00\x74\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_56 {
  meta:
    info = "kamine"
  strings:
    $utf8 = "\x6b\x61\x6d\x69\x6e\x65" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6d\x00\x69\x00\x6e\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_57 {
  meta:
    info = "kaminey"
  strings:
    $utf8 = "\x6b\x61\x6d\x69\x6e\x65\x79" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6d\x00\x69\x00\x6e\x00\x65\x00\x79\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_58 {
  meta:
    info = "kanjar"
  strings:
    $utf8 = "\x6b\x61\x6e\x6a\x61\x72" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6e\x00\x6a\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_60 {
  meta:
    info = "kutta kamina"
  strings:
    $utf8 = "\x6b\x75\x74\x74\x61\x20\x6b\x61\x6d\x69\x6e\x61" nocase fullword
    $wide = "\x6b\x00\x75\x00\x74\x00\x74\x00\x61\x00\x20\x00\x6b\x00\x61\x00\x6d\x00\x69\x00\x6e\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_61 {
  meta:
    info = "kutte ki aulad"
  strings:
    $utf8 = "\x6b\x75\x74\x74\x65\x20\x6b\x69\x20\x61\x75\x6c\x61\x64" nocase fullword
    $wide = "\x6b\x00\x75\x00\x74\x00\x74\x00\x65\x00\x20\x00\x6b\x00\x69\x00\x20\x00\x61\x00\x75\x00\x6c\x00\x61\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_62 {
  meta:
    info = "kutte ki jat"
  strings:
    $utf8 = "\x6b\x75\x74\x74\x65\x20\x6b\x69\x20\x6a\x61\x74" nocase fullword
    $wide = "\x6b\x00\x75\x00\x74\x00\x74\x00\x65\x00\x20\x00\x6b\x00\x69\x00\x20\x00\x6a\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_63 {
  meta:
    info = "kuttiya"
  strings:
    $utf8 = "\x6b\x75\x74\x74\x69\x79\x61" nocase fullword
    $wide = "\x6b\x00\x75\x00\x74\x00\x74\x00\x69\x00\x79\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_64 {
  meta:
    info = "loda"
  strings:
    $utf8 = "\x6c\x6f\x64\x61" nocase fullword
    $wide = "\x6c\x00\x6f\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_65 {
  meta:
    info = "lodu"
  strings:
    $utf8 = "\x6c\x6f\x64\x75" nocase fullword
    $wide = "\x6c\x00\x6f\x00\x64\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_66 {
  meta:
    info = "lund"
  strings:
    $utf8 = "\x6c\x75\x6e\x64" nocase fullword
    $wide = "\x6c\x00\x75\x00\x6e\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_67 {
  meta:
    info = "lund choos"
  strings:
    $utf8 = "\x6c\x75\x6e\x64\x20\x63\x68\x6f\x6f\x73" nocase fullword
    $wide = "\x6c\x00\x75\x00\x6e\x00\x64\x00\x20\x00\x63\x00\x68\x00\x6f\x00\x6f\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_68 {
  meta:
    info = "lund khajoor"
  strings:
    $utf8 = "\x6c\x75\x6e\x64\x20\x6b\x68\x61\x6a\x6f\x6f\x72" nocase fullword
    $wide = "\x6c\x00\x75\x00\x6e\x00\x64\x00\x20\x00\x6b\x00\x68\x00\x61\x00\x6a\x00\x6f\x00\x6f\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_69 {
  meta:
    info = "lundtopi"
  strings:
    $utf8 = "\x6c\x75\x6e\x64\x74\x6f\x70\x69" nocase fullword
    $wide = "\x6c\x00\x75\x00\x6e\x00\x64\x00\x74\x00\x6f\x00\x70\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_70 {
  meta:
    info = "lundure"
  strings:
    $utf8 = "\x6c\x75\x6e\x64\x75\x72\x65" nocase fullword
    $wide = "\x6c\x00\x75\x00\x6e\x00\x64\x00\x75\x00\x72\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_71 {
  meta:
    info = "maa ki chut"
  strings:
    $utf8 = "\x6d\x61\x61\x20\x6b\x69\x20\x63\x68\x75\x74" nocase fullword
    $wide = "\x6d\x00\x61\x00\x61\x00\x20\x00\x6b\x00\x69\x00\x20\x00\x63\x00\x68\x00\x75\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_72 {
  meta:
    info = "maal"
  strings:
    $utf8 = "\x6d\x61\x61\x6c" nocase fullword
    $wide = "\x6d\x00\x61\x00\x61\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_73 {
  meta:
    info = "madar chod"
  strings:
    $utf8 = "\x6d\x61\x64\x61\x72\x20\x63\x68\x6f\x64" nocase fullword
    $wide = "\x6d\x00\x61\x00\x64\x00\x61\x00\x72\x00\x20\x00\x63\x00\x68\x00\x6f\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_74 {
  meta:
    info = "mooh mein le"
  strings:
    $utf8 = "\x6d\x6f\x6f\x68\x20\x6d\x65\x69\x6e\x20\x6c\x65" nocase fullword
    $wide = "\x6d\x00\x6f\x00\x6f\x00\x68\x00\x20\x00\x6d\x00\x65\x00\x69\x00\x6e\x00\x20\x00\x6c\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_75 {
  meta:
    info = "mutth"
  strings:
    $utf8 = "\x6d\x75\x74\x74\x68" nocase fullword
    $wide = "\x6d\x00\x75\x00\x74\x00\x74\x00\x68\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_76 {
  meta:
    info = "najayaz"
  strings:
    $utf8 = "\x6e\x61\x6a\x61\x79\x61\x7a" nocase fullword
    $wide = "\x6e\x00\x61\x00\x6a\x00\x61\x00\x79\x00\x61\x00\x7a\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_77 {
  meta:
    info = "najayaz aulaad"
  strings:
    $utf8 = "\x6e\x61\x6a\x61\x79\x61\x7a\x20\x61\x75\x6c\x61\x61\x64" nocase fullword
    $wide = "\x6e\x00\x61\x00\x6a\x00\x61\x00\x79\x00\x61\x00\x7a\x00\x20\x00\x61\x00\x75\x00\x6c\x00\x61\x00\x61\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_78 {
  meta:
    info = "najayaz paidaish"
  strings:
    $utf8 = "\x6e\x61\x6a\x61\x79\x61\x7a\x20\x70\x61\x69\x64\x61\x69\x73\x68" nocase fullword
    $wide = "\x6e\x00\x61\x00\x6a\x00\x61\x00\x79\x00\x61\x00\x7a\x00\x20\x00\x70\x00\x61\x00\x69\x00\x64\x00\x61\x00\x69\x00\x73\x00\x68\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_79 {
  meta:
    info = "paki"
  strings:
    $utf8 = "\x70\x61\x6b\x69" nocase fullword
    $wide = "\x70\x00\x61\x00\x6b\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_80 {
  meta:
    info = "pataka"
  strings:
    $utf8 = "\x70\x61\x74\x61\x6b\x61" nocase fullword
    $wide = "\x70\x00\x61\x00\x74\x00\x61\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_81 {
  meta:
    info = "patakha"
  strings:
    $utf8 = "\x70\x61\x74\x61\x6b\x68\x61" nocase fullword
    $wide = "\x70\x00\x61\x00\x74\x00\x61\x00\x6b\x00\x68\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_82 {
  meta:
    info = "raand"
  strings:
    $utf8 = "\x72\x61\x61\x6e\x64" nocase fullword
    $wide = "\x72\x00\x61\x00\x61\x00\x6e\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_83 {
  meta:
    info = "randi"
  strings:
    $utf8 = "\x72\x61\x6e\x64\x69" nocase fullword
    $wide = "\x72\x00\x61\x00\x6e\x00\x64\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_84 {
  meta:
    info = "saala"
  strings:
    $utf8 = "\x73\x61\x61\x6c\x61" nocase fullword
    $wide = "\x73\x00\x61\x00\x61\x00\x6c\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_85 {
  meta:
    info = "saala kutta"
  strings:
    $utf8 = "\x73\x61\x61\x6c\x61\x20\x6b\x75\x74\x74\x61" nocase fullword
    $wide = "\x73\x00\x61\x00\x61\x00\x6c\x00\x61\x00\x20\x00\x6b\x00\x75\x00\x74\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_86 {
  meta:
    info = "saali kutti"
  strings:
    $utf8 = "\x73\x61\x61\x6c\x69\x20\x6b\x75\x74\x74\x69" nocase fullword
    $wide = "\x73\x00\x61\x00\x61\x00\x6c\x00\x69\x00\x20\x00\x6b\x00\x75\x00\x74\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_87 {
  meta:
    info = "saali randi"
  strings:
    $utf8 = "\x73\x61\x61\x6c\x69\x20\x72\x61\x6e\x64\x69" nocase fullword
    $wide = "\x73\x00\x61\x00\x61\x00\x6c\x00\x69\x00\x20\x00\x72\x00\x61\x00\x6e\x00\x64\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_88 {
  meta:
    info = "suar"
  strings:
    $utf8 = "\x73\x75\x61\x72" nocase fullword
    $wide = "\x73\x00\x75\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_89 {
  meta:
    info = "suar ki aulad"
  strings:
    $utf8 = "\x73\x75\x61\x72\x20\x6b\x69\x20\x61\x75\x6c\x61\x64" nocase fullword
    $wide = "\x73\x00\x75\x00\x61\x00\x72\x00\x20\x00\x6b\x00\x69\x00\x20\x00\x61\x00\x75\x00\x6c\x00\x61\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_90 {
  meta:
    info = "tatte"
  strings:
    $utf8 = "\x74\x61\x74\x74\x65" nocase fullword
    $wide = "\x74\x00\x61\x00\x74\x00\x74\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_91 {
  meta:
    info = "tatti"
  strings:
    $utf8 = "\x74\x61\x74\x74\x69" nocase fullword
    $wide = "\x74\x00\x61\x00\x74\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_92 {
  meta:
    info = "teri maa ka bhosada"
  strings:
    $utf8 = "\x74\x65\x72\x69\x20\x6d\x61\x61\x20\x6b\x61\x20\x62\x68\x6f\x73\x61\x64\x61" nocase fullword
    $wide = "\x74\x00\x65\x00\x72\x00\x69\x00\x20\x00\x6d\x00\x61\x00\x61\x00\x20\x00\x6b\x00\x61\x00\x20\x00\x62\x00\x68\x00\x6f\x00\x73\x00\x61\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_93 {
  meta:
    info = "teri maa ka boba chusu"
  strings:
    $utf8 = "\x74\x65\x72\x69\x20\x6d\x61\x61\x20\x6b\x61\x20\x62\x6f\x62\x61\x20\x63\x68\x75\x73\x75" nocase fullword
    $wide = "\x74\x00\x65\x00\x72\x00\x69\x00\x20\x00\x6d\x00\x61\x00\x61\x00\x20\x00\x6b\x00\x61\x00\x20\x00\x62\x00\x6f\x00\x62\x00\x61\x00\x20\x00\x63\x00\x68\x00\x75\x00\x73\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_94 {
  meta:
    info = "teri maa ki chut"
  strings:
    $utf8 = "\x74\x65\x72\x69\x20\x6d\x61\x61\x20\x6b\x69\x20\x63\x68\x75\x74" nocase fullword
    $wide = "\x74\x00\x65\x00\x72\x00\x69\x00\x20\x00\x6d\x00\x61\x00\x61\x00\x20\x00\x6b\x00\x69\x00\x20\x00\x63\x00\x68\x00\x75\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_95 {
  meta:
    info = "tharak"
  strings:
    $utf8 = "\x74\x68\x61\x72\x61\x6b" nocase fullword
    $wide = "\x74\x00\x68\x00\x61\x00\x72\x00\x61\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_96 {
  meta:
    info = "tharki"
  strings:
    $utf8 = "\x74\x68\x61\x72\x6b\x69" nocase fullword
    $wide = "\x74\x00\x68\x00\x61\x00\x72\x00\x6b\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_97 {
  meta:
    info = "भड़वा"
  strings:
    $utf8 = "\xe0\xa4\xad\xe0\xa4\xa1\xe0\xa4\xbc\xe0\xa4\xb5\xe0\xa4\xbe" nocase fullword
    $wide = "\x2d\x09\x21\x09\x3c\x09\x35\x09\x3e\x09" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_98 {
  meta:
    info = "रंडी"
  strings:
    $utf8 = "\xe0\xa4\xb0\xe0\xa4\x82\xe0\xa4\xa1\xe0\xa5\x80" nocase fullword
    $wide = "\x30\x09\x02\x09\x21\x09\x40\x09" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_99 {
  meta:
    info = "गांड"
  strings:
    $utf8 = "\xe0\xa4\x97\xe0\xa4\xbe\xe0\xa4\x82\xe0\xa4\xa1" nocase fullword
    $wide = "\x17\x09\x3e\x09\x02\x09\x21\x09" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_100 {
  meta:
    info = "चूत"
  strings:
    $utf8 = "\xe0\xa4\x9a\xe0\xa5\x82\xe0\xa4\xa4" nocase fullword
    $wide = "\x1a\x09\x42\x09\x24\x09" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_101 {
  meta:
    info = "लंड"
  strings:
    $utf8 = "\xe0\xa4\xb2\xe0\xa4\x82\xe0\xa4\xa1" nocase fullword
    $wide = "\x32\x09\x02\x09\x21\x09" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_102 {
  meta:
    info = "चोदना"
  strings:
    $utf8 = "\xe0\xa4\x9a\xe0\xa5\x8b\xe0\xa4\xa6\xe0\xa4\xa8\xe0\xa4\xbe" nocase fullword
    $wide = "\x1a\x09\x4b\x09\x26\x09\x28\x09\x3e\x09" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_103 {
  meta:
    info = "मादरचोद"
  strings:
    $utf8 = "\xe0\xa4\xae\xe0\xa4\xbe\xe0\xa4\xa6\xe0\xa4\xb0\xe0\xa4\x9a\xe0\xa5\x8b\xe0\xa4\xa6" nocase fullword
    $wide = "\x2e\x09\x3e\x09\x26\x09\x30\x09\x1a\x09\x4b\x09\x26\x09" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_104 {
  meta:
    info = "भोसड़ीके"
  strings:
    $utf8 = "\xe0\xa4\xad\xe0\xa5\x8b\xe0\xa4\xb8\xe0\xa4\xa1\xe0\xa4\xbc\xe0\xa5\x80\xe0\xa4\x95\xe0\xa5\x87" nocase fullword
    $wide = "\x2d\x09\x4b\x09\x38\x09\x21\x09\x3c\x09\x40\x09\x15\x09\x47\x09" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_105 {
  meta:
    info = "चूतिया"
  strings:
    $utf8 = "\xe0\xa4\x9a\xe0\xa5\x82\xe0\xa4\xa4\xe0\xa4\xbf\xe0\xa4\xaf\xe0\xa4\xbe" nocase fullword
    $wide = "\x1a\x09\x42\x09\x24\x09\x3f\x09\x2f\x09\x3e\x09" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_106 {
  meta:
    info = "बहनचोद"
  strings:
    $utf8 = "\xe0\xa4\xac\xe0\xa4\xb9\xe0\xa4\xa8\xe0\xa4\x9a\xe0\xa5\x8b\xe0\xa4\xa6" nocase fullword
    $wide = "\x2c\x09\x39\x09\x28\x09\x1a\x09\x4b\x09\x26\x09" nocase fullword
  condition:
    any of them
}
rule content_hi_language_nsfw_107 {
  meta:
    info = "लौड़ा"
  strings:
    $utf8 = "\xe0\xa4\xb2\xe0\xa5\x8c\xe0\xa4\xa1\xe0\xa4\xbc\xe0\xa4\xbe" nocase fullword
    $wide = "\x32\x09\x4c\x09\x21\x09\x3c\x09\x3e\x09" nocase fullword
  condition:
    any of them
}

rule content_hi_language_nsfw_test {
  meta:
    info = "Test rule for hi language detection - UUID: 8C9D0E1F-2A3B-44C5-D6E7-F8A9B0C1D2E3"
  strings:
    $ = "8C9D0E1F-2A3B-44C5-D6E7-F8A9B0C1D2E3" fullword wide ascii nocase
  condition:
    any of them
}
