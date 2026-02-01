rule content_cs_language_nsfw_1 {
  meta:
    info = "buzna"
  strings:
    $utf8 = "\x62\x75\x7a\x6e\x61" nocase fullword
    $wide = "\x62\x00\x75\x00\x7a\x00\x6e\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_2 {
  meta:
    info = "chcanky"
  strings:
    $utf8 = "\x63\x68\x63\x61\x6e\x6b\x79" nocase fullword
    $wide = "\x63\x00\x68\x00\x63\x00\x61\x00\x6e\x00\x6b\x00\x79\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_3 {
  meta:
    info = "chuj"
  strings:
    $utf8 = "\x63\x68\x75\x6a" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x6a\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_4 {
  meta:
    info = "do piče"
  strings:
    $utf8 = "\x64\x6f\x20\x70\x69\xc4\x8d\x65" nocase fullword
    $wide = "\x64\x00\x6f\x00\x20\x00\x70\x00\x69\x00\x0d\x01\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_5 {
  meta:
    info = "do prdele"
  strings:
    $utf8 = "\x64\x6f\x20\x70\x72\x64\x65\x6c\x65" nocase fullword
    $wide = "\x64\x00\x6f\x00\x20\x00\x70\x00\x72\x00\x64\x00\x65\x00\x6c\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_6 {
  meta:
    info = "držka"
  strings:
    $utf8 = "\x64\x72\xc5\xbe\x6b\x61" nocase fullword
    $wide = "\x64\x00\x72\x00\x7e\x01\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_7 {
  meta:
    info = "dršťka"
  strings:
    $utf8 = "\x64\x72\xc5\xa1\xc5\xa5\x6b\x61" nocase fullword
    $wide = "\x64\x00\x72\x00\x61\x01\x65\x01\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_8 {
  meta:
    info = "flundra"
  strings:
    $utf8 = "\x66\x6c\x75\x6e\x64\x72\x61" nocase fullword
    $wide = "\x66\x00\x6c\x00\x75\x00\x6e\x00\x64\x00\x72\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_9 {
  meta:
    info = "hajzl"
  strings:
    $utf8 = "\x68\x61\x6a\x7a\x6c" nocase fullword
    $wide = "\x68\x00\x61\x00\x6a\x00\x7a\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_10 {
  meta:
    info = "hovno"
  strings:
    $utf8 = "\x68\x6f\x76\x6e\x6f" nocase fullword
    $wide = "\x68\x00\x6f\x00\x76\x00\x6e\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_11 {
  meta:
    info = "jebat"
  strings:
    $utf8 = "\x6a\x65\x62\x61\x74" nocase fullword
    $wide = "\x6a\x00\x65\x00\x62\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_12 {
  meta:
    info = "kokot"
  strings:
    $utf8 = "\x6b\x6f\x6b\x6f\x74" nocase fullword
    $wide = "\x6b\x00\x6f\x00\x6b\x00\x6f\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_13 {
  meta:
    info = "kokotina"
  strings:
    $utf8 = "\x6b\x6f\x6b\x6f\x74\x69\x6e\x61" nocase fullword
    $wide = "\x6b\x00\x6f\x00\x6b\x00\x6f\x00\x74\x00\x69\x00\x6e\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_14 {
  meta:
    info = "koňomrd"
  strings:
    $utf8 = "\x6b\x6f\xc5\x88\x6f\x6d\x72\x64" nocase fullword
    $wide = "\x6b\x00\x6f\x00\x48\x01\x6f\x00\x6d\x00\x72\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_15 {
  meta:
    info = "kunda"
  strings:
    $utf8 = "\x6b\x75\x6e\x64\x61" nocase fullword
    $wide = "\x6b\x00\x75\x00\x6e\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_16 {
  meta:
    info = "kurva"
  strings:
    $utf8 = "\x6b\x75\x72\x76\x61" nocase fullword
    $wide = "\x6b\x00\x75\x00\x72\x00\x76\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_17 {
  meta:
    info = "mamrd"
  strings:
    $utf8 = "\x6d\x61\x6d\x72\x64" nocase fullword
    $wide = "\x6d\x00\x61\x00\x6d\x00\x72\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_18 {
  meta:
    info = "mrdat"
  strings:
    $utf8 = "\x6d\x72\x64\x61\x74" nocase fullword
    $wide = "\x6d\x00\x72\x00\x64\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_19 {
  meta:
    info = "mrdka"
  strings:
    $utf8 = "\x6d\x72\x64\x6b\x61" nocase fullword
    $wide = "\x6d\x00\x72\x00\x64\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_20 {
  meta:
    info = "mrdník"
  strings:
    $utf8 = "\x6d\x72\x64\x6e\xc3\xad\x6b" nocase fullword
    $wide = "\x6d\x00\x72\x00\x64\x00\x6e\x00\xed\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_21 {
  meta:
    info = "oslošoust"
  strings:
    $utf8 = "\x6f\x73\x6c\x6f\xc5\xa1\x6f\x75\x73\x74" nocase fullword
    $wide = "\x6f\x00\x73\x00\x6c\x00\x6f\x00\x61\x01\x6f\x00\x75\x00\x73\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_22 {
  meta:
    info = "pizda"
  strings:
    $utf8 = "\x70\x69\x7a\x64\x61" nocase fullword
    $wide = "\x70\x00\x69\x00\x7a\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_23 {
  meta:
    info = "piča"
  strings:
    $utf8 = "\x70\x69\xc4\x8d\x61" nocase fullword
    $wide = "\x70\x00\x69\x00\x0d\x01\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_24 {
  meta:
    info = "prcat"
  strings:
    $utf8 = "\x70\x72\x63\x61\x74" nocase fullword
    $wide = "\x70\x00\x72\x00\x63\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_25 {
  meta:
    info = "prdel"
  strings:
    $utf8 = "\x70\x72\x64\x65\x6c" nocase fullword
    $wide = "\x70\x00\x72\x00\x64\x00\x65\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_26 {
  meta:
    info = "prdelka"
  strings:
    $utf8 = "\x70\x72\x64\x65\x6c\x6b\x61" nocase fullword
    $wide = "\x70\x00\x72\x00\x64\x00\x65\x00\x6c\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_27 {
  meta:
    info = "píchat"
  strings:
    $utf8 = "\x70\xc3\xad\x63\x68\x61\x74" nocase fullword
    $wide = "\x70\x00\xed\x00\x63\x00\x68\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_28 {
  meta:
    info = "píčus"
  strings:
    $utf8 = "\x70\xc3\xad\xc4\x8d\x75\x73" nocase fullword
    $wide = "\x70\x00\xed\x00\x0d\x01\x75\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_29 {
  meta:
    info = "sračka"
  strings:
    $utf8 = "\x73\x72\x61\xc4\x8d\x6b\x61" nocase fullword
    $wide = "\x73\x00\x72\x00\x61\x00\x0d\x01\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_30 {
  meta:
    info = "srát"
  strings:
    $utf8 = "\x73\x72\xc3\xa1\x74" nocase fullword
    $wide = "\x73\x00\x72\x00\xe1\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_31 {
  meta:
    info = "vypíčenec"
  strings:
    $utf8 = "\x76\x79\x70\xc3\xad\xc4\x8d\x65\x6e\x65\x63" nocase fullword
    $wide = "\x76\x00\x79\x00\x70\x00\xed\x00\x0d\x01\x65\x00\x6e\x00\x65\x00\x63\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_32 {
  meta:
    info = "zkurvit"
  strings:
    $utf8 = "\x7a\x6b\x75\x72\x76\x69\x74" nocase fullword
    $wide = "\x7a\x00\x6b\x00\x75\x00\x72\x00\x76\x00\x69\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_33 {
  meta:
    info = "zkurvysyn"
  strings:
    $utf8 = "\x7a\x6b\x75\x72\x76\x79\x73\x79\x6e" nocase fullword
    $wide = "\x7a\x00\x6b\x00\x75\x00\x72\x00\x76\x00\x79\x00\x73\x00\x79\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_34 {
  meta:
    info = "zmrd"
  strings:
    $utf8 = "\x7a\x6d\x72\x64" nocase fullword
    $wide = "\x7a\x00\x6d\x00\x72\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_35 {
  meta:
    info = "šoustat"
  strings:
    $utf8 = "\xc5\xa1\x6f\x75\x73\x74\x61\x74" nocase fullword
    $wide = "\x61\x01\x6f\x00\x75\x00\x73\x00\x74\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_36 {
  meta:
    info = "šulin"
  strings:
    $utf8 = "\xc5\xa1\x75\x6c\x69\x6e" nocase fullword
    $wide = "\x61\x01\x75\x00\x6c\x00\x69\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_cs_language_nsfw_37 {
  meta:
    info = "čurák"
  strings:
    $utf8 = "\xc4\x8d\x75\x72\xc3\xa1\x6b" nocase fullword
    $wide = "\x0d\x01\x75\x00\x72\x00\xe1\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
