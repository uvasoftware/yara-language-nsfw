rule content_sv_language_nsfw_1 {
  meta:
    info = "arsle"
  strings:
    $utf8 = "\x61\x72\x73\x6c\x65" nocase fullword
    $wide = "\x61\x00\x72\x00\x73\x00\x6c\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_2 {
  meta:
    info = "brutta"
  strings:
    $utf8 = "\x62\x72\x75\x74\x74\x61" nocase fullword
    $wide = "\x62\x00\x72\x00\x75\x00\x74\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_3 {
  meta:
    info = "discofitta"
  strings:
    $utf8 = "\x64\x69\x73\x63\x6f\x66\x69\x74\x74\x61" nocase fullword
    $wide = "\x64\x00\x69\x00\x73\x00\x63\x00\x6f\x00\x66\x00\x69\x00\x74\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_4 {
  meta:
    info = "dra åt helvete"
  strings:
    $utf8 = "\x64\x72\x61\x20\xc3\xa5\x74\x20\x68\x65\x6c\x76\x65\x74\x65" nocase fullword
    $wide = "\x64\x00\x72\x00\x61\x00\x20\x00\xe5\x00\x74\x00\x20\x00\x68\x00\x65\x00\x6c\x00\x76\x00\x65\x00\x74\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_6 {
  meta:
    info = "fitta"
  strings:
    $utf8 = "\x66\x69\x74\x74\x61" nocase fullword
    $wide = "\x66\x00\x69\x00\x74\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_7 {
  meta:
    info = "fittig"
  strings:
    $utf8 = "\x66\x69\x74\x74\x69\x67" nocase fullword
    $wide = "\x66\x00\x69\x00\x74\x00\x74\x00\x69\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_8 {
  meta:
    info = "för helvete"
  strings:
    $utf8 = "\x66\xc3\xb6\x72\x20\x68\x65\x6c\x76\x65\x74\x65" nocase fullword
    $wide = "\x66\x00\xf6\x00\x72\x00\x20\x00\x68\x00\x65\x00\x6c\x00\x76\x00\x65\x00\x74\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_9 {
  meta:
    info = "helvete"
  strings:
    $utf8 = "\x68\x65\x6c\x76\x65\x74\x65" nocase fullword
    $wide = "\x68\x00\x65\x00\x6c\x00\x76\x00\x65\x00\x74\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_11 {
  meta:
    info = "jävlar"
  strings:
    $utf8 = "\x6a\xc3\xa4\x76\x6c\x61\x72" nocase fullword
    $wide = "\x6a\x00\xe4\x00\x76\x00\x6c\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_12 {
  meta:
    info = "knulla"
  strings:
    $utf8 = "\x6b\x6e\x75\x6c\x6c\x61" nocase fullword
    $wide = "\x6b\x00\x6e\x00\x75\x00\x6c\x00\x6c\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_13 {
  meta:
    info = "kuk"
  strings:
    $utf8 = "\x6b\x75\x6b" nocase fullword
    $wide = "\x6b\x00\x75\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_14 {
  meta:
    info = "kuksås"
  strings:
    $utf8 = "\x6b\x75\x6b\x73\xc3\xa5\x73" nocase fullword
    $wide = "\x6b\x00\x75\x00\x6b\x00\x73\x00\xe5\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_15 {
  meta:
    info = "kötthuvud"
  strings:
    $utf8 = "\x6b\xc3\xb6\x74\x74\x68\x75\x76\x75\x64" nocase fullword
    $wide = "\x6b\x00\xf6\x00\x74\x00\x74\x00\x68\x00\x75\x00\x76\x00\x75\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_16 {
  meta:
    info = "köttnacke"
  strings:
    $utf8 = "\x6b\xc3\xb6\x74\x74\x6e\x61\x63\x6b\x65" nocase fullword
    $wide = "\x6b\x00\xf6\x00\x74\x00\x74\x00\x6e\x00\x61\x00\x63\x00\x6b\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_17 {
  meta:
    info = "moona"
  strings:
    $utf8 = "\x6d\x6f\x6f\x6e\x61" nocase fullword
    $wide = "\x6d\x00\x6f\x00\x6f\x00\x6e\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_18 {
  meta:
    info = "moonade"
  strings:
    $utf8 = "\x6d\x6f\x6f\x6e\x61\x64\x65" nocase fullword
    $wide = "\x6d\x00\x6f\x00\x6f\x00\x6e\x00\x61\x00\x64\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_19 {
  meta:
    info = "moonar"
  strings:
    $utf8 = "\x6d\x6f\x6f\x6e\x61\x72" nocase fullword
    $wide = "\x6d\x00\x6f\x00\x6f\x00\x6e\x00\x61\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_20 {
  meta:
    info = "moonat"
  strings:
    $utf8 = "\x6d\x6f\x6f\x6e\x61\x74" nocase fullword
    $wide = "\x6d\x00\x6f\x00\x6f\x00\x6e\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_21 {
  meta:
    info = "mutta"
  strings:
    $utf8 = "\x6d\x75\x74\x74\x61" nocase fullword
    $wide = "\x6d\x00\x75\x00\x74\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_22 {
  meta:
    info = "neger"
  strings:
    $utf8 = "\x6e\x65\x67\x65\x72" nocase fullword
    $wide = "\x6e\x00\x65\x00\x67\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_23 {
  meta:
    info = "nigger"
  strings:
    $utf8 = "\x6e\x69\x67\x67\x65\x72" nocase fullword
    $wide = "\x6e\x00\x69\x00\x67\x00\x67\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_25 {
  meta:
    info = "pippa"
  strings:
    $utf8 = "\x70\x69\x70\x70\x61" nocase fullword
    $wide = "\x70\x00\x69\x00\x70\x00\x70\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_28 {
  meta:
    info = "pök"
  strings:
    $utf8 = "\x70\xc3\xb6\x6b" nocase fullword
    $wide = "\x70\x00\xf6\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_29 {
  meta:
    info = "runka"
  strings:
    $utf8 = "\x72\x75\x6e\x6b\x61" nocase fullword
    $wide = "\x72\x00\x75\x00\x6e\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_30 {
  meta:
    info = "röv"
  strings:
    $utf8 = "\x72\xc3\xb6\x76" nocase fullword
    $wide = "\x72\x00\xf6\x00\x76\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_31 {
  meta:
    info = "rövhål"
  strings:
    $utf8 = "\x72\xc3\xb6\x76\x68\xc3\xa5\x6c" nocase fullword
    $wide = "\x72\x00\xf6\x00\x76\x00\x68\x00\xe5\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_32 {
  meta:
    info = "rövknulla"
  strings:
    $utf8 = "\x72\xc3\xb6\x76\x6b\x6e\x75\x6c\x6c\x61" nocase fullword
    $wide = "\x72\x00\xf6\x00\x76\x00\x6b\x00\x6e\x00\x75\x00\x6c\x00\x6c\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_33 {
  meta:
    info = "satan"
  strings:
    $utf8 = "\x73\x61\x74\x61\x6e" nocase fullword
    $wide = "\x73\x00\x61\x00\x74\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_34 {
  meta:
    info = "skit ner dig"
  strings:
    $utf8 = "\x73\x6b\x69\x74\x20\x6e\x65\x72\x20\x64\x69\x67" nocase fullword
    $wide = "\x73\x00\x6b\x00\x69\x00\x74\x00\x20\x00\x6e\x00\x65\x00\x72\x00\x20\x00\x64\x00\x69\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_35 {
  meta:
    info = "skita"
  strings:
    $utf8 = "\x73\x6b\x69\x74\x61" nocase fullword
    $wide = "\x73\x00\x6b\x00\x69\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_36 {
  meta:
    info = "skäggbiff"
  strings:
    $utf8 = "\x73\x6b\xc3\xa4\x67\x67\x62\x69\x66\x66" nocase fullword
    $wide = "\x73\x00\x6b\x00\xe4\x00\x67\x00\x67\x00\x62\x00\x69\x00\x66\x00\x66\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_37 {
  meta:
    info = "snedfitta"
  strings:
    $utf8 = "\x73\x6e\x65\x64\x66\x69\x74\x74\x61" nocase fullword
    $wide = "\x73\x00\x6e\x00\x65\x00\x64\x00\x66\x00\x69\x00\x74\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_38 {
  meta:
    info = "snefitta"
  strings:
    $utf8 = "\x73\x6e\x65\x66\x69\x74\x74\x61" nocase fullword
    $wide = "\x73\x00\x6e\x00\x65\x00\x66\x00\x69\x00\x74\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_40 {
  meta:
    info = "subba"
  strings:
    $utf8 = "\x73\x75\x62\x62\x61" nocase fullword
    $wide = "\x73\x00\x75\x00\x62\x00\x62\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_41 {
  meta:
    info = "sätta på"
  strings:
    $utf8 = "\x73\xc3\xa4\x74\x74\x61\x20\x70\xc3\xa5" nocase fullword
    $wide = "\x73\x00\xe4\x00\x74\x00\x74\x00\x61\x00\x20\x00\x70\x00\xe5\x00" nocase fullword
  condition:
    any of them
}
rule content_sv_language_nsfw_43 {
  meta:
    info = "tusan"
  strings:
    $utf8 = "\x74\x75\x73\x61\x6e" nocase fullword
    $wide = "\x74\x00\x75\x00\x73\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
