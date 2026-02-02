rule content_tr_language_nsfw_1 {
  meta:
    info = "amcık"
  strings:
    $utf8 = "\x61\x6d\x63\xc4\xb1\x6b" nocase fullword
    $wide = "\x61\x00\x6d\x00\x63\x00\x31\x01\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_2 {
  meta:
    info = "amcıklar"
  strings:
    $utf8 = "\x61\x6d\x63\xc4\xb1\x6b\x6c\x61\x72" nocase fullword
    $wide = "\x61\x00\x6d\x00\x63\x00\x31\x01\x6b\x00\x6c\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_3 {
  meta:
    info = "amcıklara"
  strings:
    $utf8 = "\x61\x6d\x63\xc4\xb1\x6b\x6c\x61\x72\x61" nocase fullword
    $wide = "\x61\x00\x6d\x00\x63\x00\x31\x01\x6b\x00\x6c\x00\x61\x00\x72\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_4 {
  meta:
    info = "amcıklarda"
  strings:
    $utf8 = "\x61\x6d\x63\xc4\xb1\x6b\x6c\x61\x72\x64\x61" nocase fullword
    $wide = "\x61\x00\x6d\x00\x63\x00\x31\x01\x6b\x00\x6c\x00\x61\x00\x72\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_5 {
  meta:
    info = "amcıklardan"
  strings:
    $utf8 = "\x61\x6d\x63\xc4\xb1\x6b\x6c\x61\x72\x64\x61\x6e" nocase fullword
    $wide = "\x61\x00\x6d\x00\x63\x00\x31\x01\x6b\x00\x6c\x00\x61\x00\x72\x00\x64\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_6 {
  meta:
    info = "amcıkları"
  strings:
    $utf8 = "\x61\x6d\x63\xc4\xb1\x6b\x6c\x61\x72\xc4\xb1" nocase fullword
    $wide = "\x61\x00\x6d\x00\x63\x00\x31\x01\x6b\x00\x6c\x00\x61\x00\x72\x00\x31\x01" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_7 {
  meta:
    info = "amcıkların"
  strings:
    $utf8 = "\x61\x6d\x63\xc4\xb1\x6b\x6c\x61\x72\xc4\xb1\x6e" nocase fullword
    $wide = "\x61\x00\x6d\x00\x63\x00\x31\x01\x6b\x00\x6c\x00\x61\x00\x72\x00\x31\x01\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_8 {
  meta:
    info = "amcıkta"
  strings:
    $utf8 = "\x61\x6d\x63\xc4\xb1\x6b\x74\x61" nocase fullword
    $wide = "\x61\x00\x6d\x00\x63\x00\x31\x01\x6b\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_9 {
  meta:
    info = "amcıktan"
  strings:
    $utf8 = "\x61\x6d\x63\xc4\xb1\x6b\x74\x61\x6e" nocase fullword
    $wide = "\x61\x00\x6d\x00\x63\x00\x31\x01\x6b\x00\x74\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_10 {
  meta:
    info = "amcığa"
  strings:
    $utf8 = "\x61\x6d\x63\xc4\xb1\xc4\x9f\x61" nocase fullword
    $wide = "\x61\x00\x6d\x00\x63\x00\x31\x01\x1f\x01\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_11 {
  meta:
    info = "amcığı"
  strings:
    $utf8 = "\x61\x6d\x63\xc4\xb1\xc4\x9f\xc4\xb1" nocase fullword
    $wide = "\x61\x00\x6d\x00\x63\x00\x31\x01\x1f\x01\x31\x01" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_12 {
  meta:
    info = "amcığın"
  strings:
    $utf8 = "\x61\x6d\x63\xc4\xb1\xc4\x9f\xc4\xb1\x6e" nocase fullword
    $wide = "\x61\x00\x6d\x00\x63\x00\x31\x01\x1f\x01\x31\x01\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_13 {
  meta:
    info = "amlar"
  strings:
    $utf8 = "\x61\x6d\x6c\x61\x72" nocase fullword
    $wide = "\x61\x00\x6d\x00\x6c\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_14 {
  meta:
    info = "amı"
  strings:
    $utf8 = "\x61\x6d\xc4\xb1" nocase fullword
    $wide = "\x61\x00\x6d\x00\x31\x01" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_15 {
  meta:
    info = "göt"
  strings:
    $utf8 = "\x67\xc3\xb6\x74" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_16 {
  meta:
    info = "göte"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x65" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_17 {
  meta:
    info = "götler"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x6c\x65\x72" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x6c\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_18 {
  meta:
    info = "götlerde"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x6c\x65\x72\x64\x65" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x6c\x00\x65\x00\x72\x00\x64\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_19 {
  meta:
    info = "götlerden"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x6c\x65\x72\x64\x65\x6e" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x6c\x00\x65\x00\x72\x00\x64\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_20 {
  meta:
    info = "götlere"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x6c\x65\x72\x65" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x6c\x00\x65\x00\x72\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_21 {
  meta:
    info = "götleri"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x6c\x65\x72\x69" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x6c\x00\x65\x00\x72\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_22 {
  meta:
    info = "götlerin"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x6c\x65\x72\x69\x6e" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x6c\x00\x65\x00\x72\x00\x69\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_23 {
  meta:
    info = "götte"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x74\x65" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x74\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_24 {
  meta:
    info = "götten"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x74\x65\x6e" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_25 {
  meta:
    info = "götveren"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x76\x65\x72\x65\x6e" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x76\x00\x65\x00\x72\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_26 {
  meta:
    info = "götverende"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x76\x65\x72\x65\x6e\x64\x65" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x76\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x64\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_27 {
  meta:
    info = "götverenden"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x76\x65\x72\x65\x6e\x64\x65\x6e" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x76\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x64\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_28 {
  meta:
    info = "götverene"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x76\x65\x72\x65\x6e\x65" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x76\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_29 {
  meta:
    info = "götvereni"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x76\x65\x72\x65\x6e\x69" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x76\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_30 {
  meta:
    info = "götverenin"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x76\x65\x72\x65\x6e\x69\x6e" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x76\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x69\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_31 {
  meta:
    info = "götverenler"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x76\x65\x72\x65\x6e\x6c\x65\x72" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x76\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x6c\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_32 {
  meta:
    info = "götverenlerde"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x76\x65\x72\x65\x6e\x6c\x65\x72\x64\x65" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x76\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x6c\x00\x65\x00\x72\x00\x64\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_33 {
  meta:
    info = "götverenlerden"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x76\x65\x72\x65\x6e\x6c\x65\x72\x64\x65\x6e" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x76\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x6c\x00\x65\x00\x72\x00\x64\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_34 {
  meta:
    info = "götverenlere"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x76\x65\x72\x65\x6e\x6c\x65\x72\x65" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x76\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x6c\x00\x65\x00\x72\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_35 {
  meta:
    info = "götverenleri"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x76\x65\x72\x65\x6e\x6c\x65\x72\x69" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x76\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x6c\x00\x65\x00\x72\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_36 {
  meta:
    info = "götverenlerin"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\x76\x65\x72\x65\x6e\x6c\x65\x72\x69\x6e" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\x76\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x6c\x00\x65\x00\x72\x00\x69\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_37 {
  meta:
    info = "götü"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\xc3\xbc" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\xfc\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_38 {
  meta:
    info = "götün"
  strings:
    $utf8 = "\x67\xc3\xb6\x74\xc3\xbc\x6e" nocase fullword
    $wide = "\x67\x00\xf6\x00\x74\x00\xfc\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_39 {
  meta:
    info = "kaltak"
  strings:
    $utf8 = "\x6b\x61\x6c\x74\x61\x6b" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6c\x00\x74\x00\x61\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_40 {
  meta:
    info = "kaltaklar"
  strings:
    $utf8 = "\x6b\x61\x6c\x74\x61\x6b\x6c\x61\x72" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6c\x00\x74\x00\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_41 {
  meta:
    info = "kaltaklara"
  strings:
    $utf8 = "\x6b\x61\x6c\x74\x61\x6b\x6c\x61\x72\x61" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6c\x00\x74\x00\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_42 {
  meta:
    info = "kaltaklarda"
  strings:
    $utf8 = "\x6b\x61\x6c\x74\x61\x6b\x6c\x61\x72\x64\x61" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6c\x00\x74\x00\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_43 {
  meta:
    info = "kaltaklardan"
  strings:
    $utf8 = "\x6b\x61\x6c\x74\x61\x6b\x6c\x61\x72\x64\x61\x6e" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6c\x00\x74\x00\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x64\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_44 {
  meta:
    info = "kaltakları"
  strings:
    $utf8 = "\x6b\x61\x6c\x74\x61\x6b\x6c\x61\x72\xc4\xb1" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6c\x00\x74\x00\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x31\x01" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_45 {
  meta:
    info = "kaltakların"
  strings:
    $utf8 = "\x6b\x61\x6c\x74\x61\x6b\x6c\x61\x72\xc4\xb1\x6e" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6c\x00\x74\x00\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x31\x01\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_46 {
  meta:
    info = "kaltakta"
  strings:
    $utf8 = "\x6b\x61\x6c\x74\x61\x6b\x74\x61" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6c\x00\x74\x00\x61\x00\x6b\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_47 {
  meta:
    info = "kaltaktan"
  strings:
    $utf8 = "\x6b\x61\x6c\x74\x61\x6b\x74\x61\x6e" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6c\x00\x74\x00\x61\x00\x6b\x00\x74\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_48 {
  meta:
    info = "kaltağa"
  strings:
    $utf8 = "\x6b\x61\x6c\x74\x61\xc4\x9f\x61" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6c\x00\x74\x00\x61\x00\x1f\x01\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_49 {
  meta:
    info = "kaltağı"
  strings:
    $utf8 = "\x6b\x61\x6c\x74\x61\xc4\x9f\xc4\xb1" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6c\x00\x74\x00\x61\x00\x1f\x01\x31\x01" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_50 {
  meta:
    info = "kaltağın"
  strings:
    $utf8 = "\x6b\x61\x6c\x74\x61\xc4\x9f\xc4\xb1\x6e" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6c\x00\x74\x00\x61\x00\x1f\x01\x31\x01\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_51 {
  meta:
    info = "orospu"
  strings:
    $utf8 = "\x6f\x72\x6f\x73\x70\x75" nocase fullword
    $wide = "\x6f\x00\x72\x00\x6f\x00\x73\x00\x70\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_52 {
  meta:
    info = "orospuda"
  strings:
    $utf8 = "\x6f\x72\x6f\x73\x70\x75\x64\x61" nocase fullword
    $wide = "\x6f\x00\x72\x00\x6f\x00\x73\x00\x70\x00\x75\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_53 {
  meta:
    info = "orospudan"
  strings:
    $utf8 = "\x6f\x72\x6f\x73\x70\x75\x64\x61\x6e" nocase fullword
    $wide = "\x6f\x00\x72\x00\x6f\x00\x73\x00\x70\x00\x75\x00\x64\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_54 {
  meta:
    info = "orospular"
  strings:
    $utf8 = "\x6f\x72\x6f\x73\x70\x75\x6c\x61\x72" nocase fullword
    $wide = "\x6f\x00\x72\x00\x6f\x00\x73\x00\x70\x00\x75\x00\x6c\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_55 {
  meta:
    info = "orospulara"
  strings:
    $utf8 = "\x6f\x72\x6f\x73\x70\x75\x6c\x61\x72\x61" nocase fullword
    $wide = "\x6f\x00\x72\x00\x6f\x00\x73\x00\x70\x00\x75\x00\x6c\x00\x61\x00\x72\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_56 {
  meta:
    info = "orospularda"
  strings:
    $utf8 = "\x6f\x72\x6f\x73\x70\x75\x6c\x61\x72\x64\x61" nocase fullword
    $wide = "\x6f\x00\x72\x00\x6f\x00\x73\x00\x70\x00\x75\x00\x6c\x00\x61\x00\x72\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_57 {
  meta:
    info = "orospulardan"
  strings:
    $utf8 = "\x6f\x72\x6f\x73\x70\x75\x6c\x61\x72\x64\x61\x6e" nocase fullword
    $wide = "\x6f\x00\x72\x00\x6f\x00\x73\x00\x70\x00\x75\x00\x6c\x00\x61\x00\x72\x00\x64\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_58 {
  meta:
    info = "orospuları"
  strings:
    $utf8 = "\x6f\x72\x6f\x73\x70\x75\x6c\x61\x72\xc4\xb1" nocase fullword
    $wide = "\x6f\x00\x72\x00\x6f\x00\x73\x00\x70\x00\x75\x00\x6c\x00\x61\x00\x72\x00\x31\x01" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_59 {
  meta:
    info = "orospuların"
  strings:
    $utf8 = "\x6f\x72\x6f\x73\x70\x75\x6c\x61\x72\xc4\xb1\x6e" nocase fullword
    $wide = "\x6f\x00\x72\x00\x6f\x00\x73\x00\x70\x00\x75\x00\x6c\x00\x61\x00\x72\x00\x31\x01\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_60 {
  meta:
    info = "orospunun"
  strings:
    $utf8 = "\x6f\x72\x6f\x73\x70\x75\x6e\x75\x6e" nocase fullword
    $wide = "\x6f\x00\x72\x00\x6f\x00\x73\x00\x70\x00\x75\x00\x6e\x00\x75\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_61 {
  meta:
    info = "orospuya"
  strings:
    $utf8 = "\x6f\x72\x6f\x73\x70\x75\x79\x61" nocase fullword
    $wide = "\x6f\x00\x72\x00\x6f\x00\x73\x00\x70\x00\x75\x00\x79\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_62 {
  meta:
    info = "orospuyu"
  strings:
    $utf8 = "\x6f\x72\x6f\x73\x70\x75\x79\x75" nocase fullword
    $wide = "\x6f\x00\x72\x00\x6f\x00\x73\x00\x70\x00\x75\x00\x79\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_63 {
  meta:
    info = "otuz birci"
  strings:
    $utf8 = "\x6f\x74\x75\x7a\x20\x62\x69\x72\x63\x69" nocase fullword
    $wide = "\x6f\x00\x74\x00\x75\x00\x7a\x00\x20\x00\x62\x00\x69\x00\x72\x00\x63\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_64 {
  meta:
    info = "otuz bircide"
  strings:
    $utf8 = "\x6f\x74\x75\x7a\x20\x62\x69\x72\x63\x69\x64\x65" nocase fullword
    $wide = "\x6f\x00\x74\x00\x75\x00\x7a\x00\x20\x00\x62\x00\x69\x00\x72\x00\x63\x00\x69\x00\x64\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_65 {
  meta:
    info = "otuz birciden"
  strings:
    $utf8 = "\x6f\x74\x75\x7a\x20\x62\x69\x72\x63\x69\x64\x65\x6e" nocase fullword
    $wide = "\x6f\x00\x74\x00\x75\x00\x7a\x00\x20\x00\x62\x00\x69\x00\x72\x00\x63\x00\x69\x00\x64\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_66 {
  meta:
    info = "otuz birciler"
  strings:
    $utf8 = "\x6f\x74\x75\x7a\x20\x62\x69\x72\x63\x69\x6c\x65\x72" nocase fullword
    $wide = "\x6f\x00\x74\x00\x75\x00\x7a\x00\x20\x00\x62\x00\x69\x00\x72\x00\x63\x00\x69\x00\x6c\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_67 {
  meta:
    info = "otuz bircilerde"
  strings:
    $utf8 = "\x6f\x74\x75\x7a\x20\x62\x69\x72\x63\x69\x6c\x65\x72\x64\x65" nocase fullword
    $wide = "\x6f\x00\x74\x00\x75\x00\x7a\x00\x20\x00\x62\x00\x69\x00\x72\x00\x63\x00\x69\x00\x6c\x00\x65\x00\x72\x00\x64\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_68 {
  meta:
    info = "otuz bircilerden"
  strings:
    $utf8 = "\x6f\x74\x75\x7a\x20\x62\x69\x72\x63\x69\x6c\x65\x72\x64\x65\x6e" nocase fullword
    $wide = "\x6f\x00\x74\x00\x75\x00\x7a\x00\x20\x00\x62\x00\x69\x00\x72\x00\x63\x00\x69\x00\x6c\x00\x65\x00\x72\x00\x64\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_69 {
  meta:
    info = "otuz bircilere"
  strings:
    $utf8 = "\x6f\x74\x75\x7a\x20\x62\x69\x72\x63\x69\x6c\x65\x72\x65" nocase fullword
    $wide = "\x6f\x00\x74\x00\x75\x00\x7a\x00\x20\x00\x62\x00\x69\x00\x72\x00\x63\x00\x69\x00\x6c\x00\x65\x00\x72\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_70 {
  meta:
    info = "otuz bircileri"
  strings:
    $utf8 = "\x6f\x74\x75\x7a\x20\x62\x69\x72\x63\x69\x6c\x65\x72\x69" nocase fullword
    $wide = "\x6f\x00\x74\x00\x75\x00\x7a\x00\x20\x00\x62\x00\x69\x00\x72\x00\x63\x00\x69\x00\x6c\x00\x65\x00\x72\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_71 {
  meta:
    info = "otuz bircilerin"
  strings:
    $utf8 = "\x6f\x74\x75\x7a\x20\x62\x69\x72\x63\x69\x6c\x65\x72\x69\x6e" nocase fullword
    $wide = "\x6f\x00\x74\x00\x75\x00\x7a\x00\x20\x00\x62\x00\x69\x00\x72\x00\x63\x00\x69\x00\x6c\x00\x65\x00\x72\x00\x69\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_72 {
  meta:
    info = "otuz bircinin"
  strings:
    $utf8 = "\x6f\x74\x75\x7a\x20\x62\x69\x72\x63\x69\x6e\x69\x6e" nocase fullword
    $wide = "\x6f\x00\x74\x00\x75\x00\x7a\x00\x20\x00\x62\x00\x69\x00\x72\x00\x63\x00\x69\x00\x6e\x00\x69\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_73 {
  meta:
    info = "otuz birciye"
  strings:
    $utf8 = "\x6f\x74\x75\x7a\x20\x62\x69\x72\x63\x69\x79\x65" nocase fullword
    $wide = "\x6f\x00\x74\x00\x75\x00\x7a\x00\x20\x00\x62\x00\x69\x00\x72\x00\x63\x00\x69\x00\x79\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_74 {
  meta:
    info = "otuz birciyi"
  strings:
    $utf8 = "\x6f\x74\x75\x7a\x20\x62\x69\x72\x63\x69\x79\x69" nocase fullword
    $wide = "\x6f\x00\x74\x00\x75\x00\x7a\x00\x20\x00\x62\x00\x69\x00\x72\x00\x63\x00\x69\x00\x79\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_75 {
  meta:
    info = "saksocu"
  strings:
    $utf8 = "\x73\x61\x6b\x73\x6f\x63\x75" nocase fullword
    $wide = "\x73\x00\x61\x00\x6b\x00\x73\x00\x6f\x00\x63\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_76 {
  meta:
    info = "saksocuda"
  strings:
    $utf8 = "\x73\x61\x6b\x73\x6f\x63\x75\x64\x61" nocase fullword
    $wide = "\x73\x00\x61\x00\x6b\x00\x73\x00\x6f\x00\x63\x00\x75\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_77 {
  meta:
    info = "saksocudan"
  strings:
    $utf8 = "\x73\x61\x6b\x73\x6f\x63\x75\x64\x61\x6e" nocase fullword
    $wide = "\x73\x00\x61\x00\x6b\x00\x73\x00\x6f\x00\x63\x00\x75\x00\x64\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_78 {
  meta:
    info = "saksocular"
  strings:
    $utf8 = "\x73\x61\x6b\x73\x6f\x63\x75\x6c\x61\x72" nocase fullword
    $wide = "\x73\x00\x61\x00\x6b\x00\x73\x00\x6f\x00\x63\x00\x75\x00\x6c\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_79 {
  meta:
    info = "saksoculara"
  strings:
    $utf8 = "\x73\x61\x6b\x73\x6f\x63\x75\x6c\x61\x72\x61" nocase fullword
    $wide = "\x73\x00\x61\x00\x6b\x00\x73\x00\x6f\x00\x63\x00\x75\x00\x6c\x00\x61\x00\x72\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_80 {
  meta:
    info = "saksocularda"
  strings:
    $utf8 = "\x73\x61\x6b\x73\x6f\x63\x75\x6c\x61\x72\x64\x61" nocase fullword
    $wide = "\x73\x00\x61\x00\x6b\x00\x73\x00\x6f\x00\x63\x00\x75\x00\x6c\x00\x61\x00\x72\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_81 {
  meta:
    info = "saksoculardan"
  strings:
    $utf8 = "\x73\x61\x6b\x73\x6f\x63\x75\x6c\x61\x72\x64\x61\x6e" nocase fullword
    $wide = "\x73\x00\x61\x00\x6b\x00\x73\x00\x6f\x00\x63\x00\x75\x00\x6c\x00\x61\x00\x72\x00\x64\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_82 {
  meta:
    info = "saksocuları"
  strings:
    $utf8 = "\x73\x61\x6b\x73\x6f\x63\x75\x6c\x61\x72\xc4\xb1" nocase fullword
    $wide = "\x73\x00\x61\x00\x6b\x00\x73\x00\x6f\x00\x63\x00\x75\x00\x6c\x00\x61\x00\x72\x00\x31\x01" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_83 {
  meta:
    info = "saksocuların"
  strings:
    $utf8 = "\x73\x61\x6b\x73\x6f\x63\x75\x6c\x61\x72\xc4\xb1\x6e" nocase fullword
    $wide = "\x73\x00\x61\x00\x6b\x00\x73\x00\x6f\x00\x63\x00\x75\x00\x6c\x00\x61\x00\x72\x00\x31\x01\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_84 {
  meta:
    info = "saksocunun"
  strings:
    $utf8 = "\x73\x61\x6b\x73\x6f\x63\x75\x6e\x75\x6e" nocase fullword
    $wide = "\x73\x00\x61\x00\x6b\x00\x73\x00\x6f\x00\x63\x00\x75\x00\x6e\x00\x75\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_85 {
  meta:
    info = "saksocuya"
  strings:
    $utf8 = "\x73\x61\x6b\x73\x6f\x63\x75\x79\x61" nocase fullword
    $wide = "\x73\x00\x61\x00\x6b\x00\x73\x00\x6f\x00\x63\x00\x75\x00\x79\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_86 {
  meta:
    info = "saksocuyu"
  strings:
    $utf8 = "\x73\x61\x6b\x73\x6f\x63\x75\x79\x75" nocase fullword
    $wide = "\x73\x00\x61\x00\x6b\x00\x73\x00\x6f\x00\x63\x00\x75\x00\x79\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_87 {
  meta:
    info = "sik"
  strings:
    $utf8 = "\x73\x69\x6b" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_88 {
  meta:
    info = "sike"
  strings:
    $utf8 = "\x73\x69\x6b\x65" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_89 {
  meta:
    info = "siker sikmez"
  strings:
    $utf8 = "\x73\x69\x6b\x65\x72\x20\x73\x69\x6b\x6d\x65\x7a" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x65\x00\x72\x00\x20\x00\x73\x00\x69\x00\x6b\x00\x6d\x00\x65\x00\x7a\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_90 {
  meta:
    info = "siki"
  strings:
    $utf8 = "\x73\x69\x6b\x69" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_91 {
  meta:
    info = "sikilir sikilmez"
  strings:
    $utf8 = "\x73\x69\x6b\x69\x6c\x69\x72\x20\x73\x69\x6b\x69\x6c\x6d\x65\x7a" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x69\x00\x6c\x00\x69\x00\x72\x00\x20\x00\x73\x00\x69\x00\x6b\x00\x69\x00\x6c\x00\x6d\x00\x65\x00\x7a\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_92 {
  meta:
    info = "sikin"
  strings:
    $utf8 = "\x73\x69\x6b\x69\x6e" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x69\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_93 {
  meta:
    info = "sikler"
  strings:
    $utf8 = "\x73\x69\x6b\x6c\x65\x72" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x6c\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_94 {
  meta:
    info = "siklerde"
  strings:
    $utf8 = "\x73\x69\x6b\x6c\x65\x72\x64\x65" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x6c\x00\x65\x00\x72\x00\x64\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_95 {
  meta:
    info = "siklerden"
  strings:
    $utf8 = "\x73\x69\x6b\x6c\x65\x72\x64\x65\x6e" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x6c\x00\x65\x00\x72\x00\x64\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_96 {
  meta:
    info = "siklere"
  strings:
    $utf8 = "\x73\x69\x6b\x6c\x65\x72\x65" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x6c\x00\x65\x00\x72\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_97 {
  meta:
    info = "sikleri"
  strings:
    $utf8 = "\x73\x69\x6b\x6c\x65\x72\x69" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x6c\x00\x65\x00\x72\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_98 {
  meta:
    info = "siklerin"
  strings:
    $utf8 = "\x73\x69\x6b\x6c\x65\x72\x69\x6e" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x6c\x00\x65\x00\x72\x00\x69\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_99 {
  meta:
    info = "sikmek"
  strings:
    $utf8 = "\x73\x69\x6b\x6d\x65\x6b" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x6d\x00\x65\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_100 {
  meta:
    info = "sikmemek"
  strings:
    $utf8 = "\x73\x69\x6b\x6d\x65\x6d\x65\x6b" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x6d\x00\x65\x00\x6d\x00\x65\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_101 {
  meta:
    info = "sikte"
  strings:
    $utf8 = "\x73\x69\x6b\x74\x65" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x74\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_102 {
  meta:
    info = "sikten"
  strings:
    $utf8 = "\x73\x69\x6b\x74\x65\x6e" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_103 {
  meta:
    info = "siktir"
  strings:
    $utf8 = "\x73\x69\x6b\x74\x69\x72" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x74\x00\x69\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_104 {
  meta:
    info = "siktirir siktirmez"
  strings:
    $utf8 = "\x73\x69\x6b\x74\x69\x72\x69\x72\x20\x73\x69\x6b\x74\x69\x72\x6d\x65\x7a" nocase fullword
    $wide = "\x73\x00\x69\x00\x6b\x00\x74\x00\x69\x00\x72\x00\x69\x00\x72\x00\x20\x00\x73\x00\x69\x00\x6b\x00\x74\x00\x69\x00\x72\x00\x6d\x00\x65\x00\x7a\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_105 {
  meta:
    info = "sıçmak"
  strings:
    $utf8 = "\x73\xc4\xb1\xc3\xa7\x6d\x61\x6b" nocase fullword
    $wide = "\x73\x00\x31\x01\xe7\x00\x6d\x00\x61\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_106 {
  meta:
    info = "taşak"
  strings:
    $utf8 = "\x74\x61\xc5\x9f\x61\x6b" nocase fullword
    $wide = "\x74\x00\x61\x00\x5f\x01\x61\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_107 {
  meta:
    info = "taşaklar"
  strings:
    $utf8 = "\x74\x61\xc5\x9f\x61\x6b\x6c\x61\x72" nocase fullword
    $wide = "\x74\x00\x61\x00\x5f\x01\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_108 {
  meta:
    info = "taşaklara"
  strings:
    $utf8 = "\x74\x61\xc5\x9f\x61\x6b\x6c\x61\x72\x61" nocase fullword
    $wide = "\x74\x00\x61\x00\x5f\x01\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_109 {
  meta:
    info = "taşaklarda"
  strings:
    $utf8 = "\x74\x61\xc5\x9f\x61\x6b\x6c\x61\x72\x64\x61" nocase fullword
    $wide = "\x74\x00\x61\x00\x5f\x01\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_110 {
  meta:
    info = "taşaklardan"
  strings:
    $utf8 = "\x74\x61\xc5\x9f\x61\x6b\x6c\x61\x72\x64\x61\x6e" nocase fullword
    $wide = "\x74\x00\x61\x00\x5f\x01\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x64\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_111 {
  meta:
    info = "taşakları"
  strings:
    $utf8 = "\x74\x61\xc5\x9f\x61\x6b\x6c\x61\x72\xc4\xb1" nocase fullword
    $wide = "\x74\x00\x61\x00\x5f\x01\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x31\x01" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_112 {
  meta:
    info = "taşakların"
  strings:
    $utf8 = "\x74\x61\xc5\x9f\x61\x6b\x6c\x61\x72\xc4\xb1\x6e" nocase fullword
    $wide = "\x74\x00\x61\x00\x5f\x01\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x31\x01\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_113 {
  meta:
    info = "taşakta"
  strings:
    $utf8 = "\x74\x61\xc5\x9f\x61\x6b\x74\x61" nocase fullword
    $wide = "\x74\x00\x61\x00\x5f\x01\x61\x00\x6b\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_114 {
  meta:
    info = "taşaktan"
  strings:
    $utf8 = "\x74\x61\xc5\x9f\x61\x6b\x74\x61\x6e" nocase fullword
    $wide = "\x74\x00\x61\x00\x5f\x01\x61\x00\x6b\x00\x74\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_115 {
  meta:
    info = "taşağa"
  strings:
    $utf8 = "\x74\x61\xc5\x9f\x61\xc4\x9f\x61" nocase fullword
    $wide = "\x74\x00\x61\x00\x5f\x01\x61\x00\x1f\x01\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_116 {
  meta:
    info = "taşağı"
  strings:
    $utf8 = "\x74\x61\xc5\x9f\x61\xc4\x9f\xc4\xb1" nocase fullword
    $wide = "\x74\x00\x61\x00\x5f\x01\x61\x00\x1f\x01\x31\x01" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_117 {
  meta:
    info = "taşağın"
  strings:
    $utf8 = "\x74\x61\xc5\x9f\x61\xc4\x9f\xc4\xb1\x6e" nocase fullword
    $wide = "\x74\x00\x61\x00\x5f\x01\x61\x00\x1f\x01\x31\x01\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_118 {
  meta:
    info = "yarak"
  strings:
    $utf8 = "\x79\x61\x72\x61\x6b" nocase fullword
    $wide = "\x79\x00\x61\x00\x72\x00\x61\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_119 {
  meta:
    info = "yaraklar"
  strings:
    $utf8 = "\x79\x61\x72\x61\x6b\x6c\x61\x72" nocase fullword
    $wide = "\x79\x00\x61\x00\x72\x00\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_120 {
  meta:
    info = "yaraklara"
  strings:
    $utf8 = "\x79\x61\x72\x61\x6b\x6c\x61\x72\x61" nocase fullword
    $wide = "\x79\x00\x61\x00\x72\x00\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_121 {
  meta:
    info = "yaraklarda"
  strings:
    $utf8 = "\x79\x61\x72\x61\x6b\x6c\x61\x72\x64\x61" nocase fullword
    $wide = "\x79\x00\x61\x00\x72\x00\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_122 {
  meta:
    info = "yaraklardan"
  strings:
    $utf8 = "\x79\x61\x72\x61\x6b\x6c\x61\x72\x64\x61\x6e" nocase fullword
    $wide = "\x79\x00\x61\x00\x72\x00\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x64\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_123 {
  meta:
    info = "yarakları"
  strings:
    $utf8 = "\x79\x61\x72\x61\x6b\x6c\x61\x72\xc4\xb1" nocase fullword
    $wide = "\x79\x00\x61\x00\x72\x00\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x31\x01" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_124 {
  meta:
    info = "yarakların"
  strings:
    $utf8 = "\x79\x61\x72\x61\x6b\x6c\x61\x72\xc4\xb1\x6e" nocase fullword
    $wide = "\x79\x00\x61\x00\x72\x00\x61\x00\x6b\x00\x6c\x00\x61\x00\x72\x00\x31\x01\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_125 {
  meta:
    info = "yarakta"
  strings:
    $utf8 = "\x79\x61\x72\x61\x6b\x74\x61" nocase fullword
    $wide = "\x79\x00\x61\x00\x72\x00\x61\x00\x6b\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_126 {
  meta:
    info = "yaraktan"
  strings:
    $utf8 = "\x79\x61\x72\x61\x6b\x74\x61\x6e" nocase fullword
    $wide = "\x79\x00\x61\x00\x72\x00\x61\x00\x6b\x00\x74\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_127 {
  meta:
    info = "yarağa"
  strings:
    $utf8 = "\x79\x61\x72\x61\xc4\x9f\x61" nocase fullword
    $wide = "\x79\x00\x61\x00\x72\x00\x61\x00\x1f\x01\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_128 {
  meta:
    info = "yarağı"
  strings:
    $utf8 = "\x79\x61\x72\x61\xc4\x9f\xc4\xb1" nocase fullword
    $wide = "\x79\x00\x61\x00\x72\x00\x61\x00\x1f\x01\x31\x01" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_129 {
  meta:
    info = "yarağın"
  strings:
    $utf8 = "\x79\x61\x72\x61\xc4\x9f\xc4\xb1\x6e" nocase fullword
    $wide = "\x79\x00\x61\x00\x72\x00\x61\x00\x1f\x01\x31\x01\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_130 {
  meta:
    info = "Çingenede"
  strings:
    $utf8 = "\xc3\x87\x69\x6e\x67\x65\x6e\x65\x64\x65" nocase fullword
    $wide = "\xc7\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x6e\x00\x65\x00\x64\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_131 {
  meta:
    info = "Çingeneden"
  strings:
    $utf8 = "\xc3\x87\x69\x6e\x67\x65\x6e\x65\x64\x65\x6e" nocase fullword
    $wide = "\xc7\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x6e\x00\x65\x00\x64\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_132 {
  meta:
    info = "Çingeneler"
  strings:
    $utf8 = "\xc3\x87\x69\x6e\x67\x65\x6e\x65\x6c\x65\x72" nocase fullword
    $wide = "\xc7\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x6e\x00\x65\x00\x6c\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_133 {
  meta:
    info = "Çingenelerde"
  strings:
    $utf8 = "\xc3\x87\x69\x6e\x67\x65\x6e\x65\x6c\x65\x72\x64\x65" nocase fullword
    $wide = "\xc7\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x6e\x00\x65\x00\x6c\x00\x65\x00\x72\x00\x64\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_134 {
  meta:
    info = "Çingenelerden"
  strings:
    $utf8 = "\xc3\x87\x69\x6e\x67\x65\x6e\x65\x6c\x65\x72\x64\x65\x6e" nocase fullword
    $wide = "\xc7\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x6e\x00\x65\x00\x6c\x00\x65\x00\x72\x00\x64\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_135 {
  meta:
    info = "Çingenelere"
  strings:
    $utf8 = "\xc3\x87\x69\x6e\x67\x65\x6e\x65\x6c\x65\x72\x65" nocase fullword
    $wide = "\xc7\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x6e\x00\x65\x00\x6c\x00\x65\x00\x72\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_136 {
  meta:
    info = "Çingeneleri"
  strings:
    $utf8 = "\xc3\x87\x69\x6e\x67\x65\x6e\x65\x6c\x65\x72\x69" nocase fullword
    $wide = "\xc7\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x6e\x00\x65\x00\x6c\x00\x65\x00\x72\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_137 {
  meta:
    info = "Çingenelerin"
  strings:
    $utf8 = "\xc3\x87\x69\x6e\x67\x65\x6e\x65\x6c\x65\x72\x69\x6e" nocase fullword
    $wide = "\xc7\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x6e\x00\x65\x00\x6c\x00\x65\x00\x72\x00\x69\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_138 {
  meta:
    info = "Çingenenin"
  strings:
    $utf8 = "\xc3\x87\x69\x6e\x67\x65\x6e\x65\x6e\x69\x6e" nocase fullword
    $wide = "\xc7\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x6e\x00\x65\x00\x6e\x00\x69\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_139 {
  meta:
    info = "Çingeneye"
  strings:
    $utf8 = "\xc3\x87\x69\x6e\x67\x65\x6e\x65\x79\x65" nocase fullword
    $wide = "\xc7\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x6e\x00\x65\x00\x79\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_140 {
  meta:
    info = "Çingeneyi"
  strings:
    $utf8 = "\xc3\x87\x69\x6e\x67\x65\x6e\x65\x79\x69" nocase fullword
    $wide = "\xc7\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x6e\x00\x65\x00\x79\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_tr_language_nsfw_141 {
  meta:
    info = "çingene"
  strings:
    $utf8 = "\xc3\xa7\x69\x6e\x67\x65\x6e\x65" nocase fullword
    $wide = "\xe7\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x6e\x00\x65\x00" nocase fullword
  condition:
    any of them
}

rule content_tr_language_nsfw_test {
  meta:
    info = "Test rule for tr language detection - UUID: 8D9E0F1A-2B3C-44D5-E6F7-A8B9C0D1E2F3"
  strings:
    $ = "8D9E0F1A-2B3C-44D5-E6F7-A8B9C0D1E2F3" fullword wide ascii nocase
  condition:
    any of them
}
