rule content_nl_language_nsfw_1 {
  meta:
    info = "achter het raam zitten"
  strings:
    $utf8 = "\x61\x63\x68\x74\x65\x72\x20\x68\x65\x74\x20\x72\x61\x61\x6d\x20\x7a\x69\x74\x74\x65\x6e" nocase fullword
    $wide = "\x61\x00\x63\x00\x68\x00\x74\x00\x65\x00\x72\x00\x20\x00\x68\x00\x65\x00\x74\x00\x20\x00\x72\x00\x61\x00\x61\x00\x6d\x00\x20\x00\x7a\x00\x69\x00\x74\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_2 {
  meta:
    info = "afberen"
  strings:
    $utf8 = "\x61\x66\x62\x65\x72\x65\x6e" nocase fullword
    $wide = "\x61\x00\x66\x00\x62\x00\x65\x00\x72\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_3 {
  meta:
    info = "aflebberen"
  strings:
    $utf8 = "\x61\x66\x6c\x65\x62\x62\x65\x72\x65\x6e" nocase fullword
    $wide = "\x61\x00\x66\x00\x6c\x00\x65\x00\x62\x00\x62\x00\x65\x00\x72\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_4 {
  meta:
    info = "afrossen"
  strings:
    $utf8 = "\x61\x66\x72\x6f\x73\x73\x65\x6e" nocase fullword
    $wide = "\x61\x00\x66\x00\x72\x00\x6f\x00\x73\x00\x73\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_5 {
  meta:
    info = "afrukken"
  strings:
    $utf8 = "\x61\x66\x72\x75\x6b\x6b\x65\x6e" nocase fullword
    $wide = "\x61\x00\x66\x00\x72\x00\x75\x00\x6b\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_6 {
  meta:
    info = "afwerkplaats"
  strings:
    $utf8 = "\x61\x66\x77\x65\x72\x6b\x70\x6c\x61\x61\x74\x73" nocase fullword
    $wide = "\x61\x00\x66\x00\x77\x00\x65\x00\x72\x00\x6b\x00\x70\x00\x6c\x00\x61\x00\x61\x00\x74\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_7 {
  meta:
    info = "afzeiken"
  strings:
    $utf8 = "\x61\x66\x7a\x65\x69\x6b\x65\x6e" nocase fullword
    $wide = "\x61\x00\x66\x00\x7a\x00\x65\x00\x69\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_8 {
  meta:
    info = "afzuigen"
  strings:
    $utf8 = "\x61\x66\x7a\x75\x69\x67\x65\x6e" nocase fullword
    $wide = "\x61\x00\x66\x00\x7a\x00\x75\x00\x69\x00\x67\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_9 {
  meta:
    info = "anderhalve man en een paardekop"
  strings:
    $utf8 = "\x61\x6e\x64\x65\x72\x68\x61\x6c\x76\x65\x20\x6d\x61\x6e\x20\x65\x6e\x20\x65\x65\x6e\x20\x70\x61\x61\x72\x64\x65\x6b\x6f\x70" nocase fullword
    $wide = "\x61\x00\x6e\x00\x64\x00\x65\x00\x72\x00\x68\x00\x61\x00\x6c\x00\x76\x00\x65\x00\x20\x00\x6d\x00\x61\x00\x6e\x00\x20\x00\x65\x00\x6e\x00\x20\x00\x65\x00\x65\x00\x6e\x00\x20\x00\x70\x00\x61\x00\x61\x00\x72\x00\x64\x00\x65\x00\x6b\x00\x6f\x00\x70\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_10 {
  meta:
    info = "bagger schijten"
  strings:
    $utf8 = "\x62\x61\x67\x67\x65\x72\x20\x73\x63\x68\x69\x6a\x74\x65\x6e" nocase fullword
    $wide = "\x62\x00\x61\x00\x67\x00\x67\x00\x65\x00\x72\x00\x20\x00\x73\x00\x63\x00\x68\x00\x69\x00\x6a\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_11 {
  meta:
    info = "bedonderen"
  strings:
    $utf8 = "\x62\x65\x64\x6f\x6e\x64\x65\x72\x65\x6e" nocase fullword
    $wide = "\x62\x00\x65\x00\x64\x00\x6f\x00\x6e\x00\x64\x00\x65\x00\x72\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_12 {
  meta:
    info = "befborstelg"
  strings:
    $utf8 = "\x62\x65\x66\x62\x6f\x72\x73\x74\x65\x6c\x67" nocase fullword
    $wide = "\x62\x00\x65\x00\x66\x00\x62\x00\x6f\x00\x72\x00\x73\x00\x74\x00\x65\x00\x6c\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_13 {
  meta:
    info = "beffen"
  strings:
    $utf8 = "\x62\x65\x66\x66\x65\x6e" nocase fullword
    $wide = "\x62\x00\x65\x00\x66\x00\x66\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_14 {
  meta:
    info = "belazeren"
  strings:
    $utf8 = "\x62\x65\x6c\x61\x7a\x65\x72\x65\x6e" nocase fullword
    $wide = "\x62\x00\x65\x00\x6c\x00\x61\x00\x7a\x00\x65\x00\x72\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_15 {
  meta:
    info = "besodemieterd zijn"
  strings:
    $utf8 = "\x62\x65\x73\x6f\x64\x65\x6d\x69\x65\x74\x65\x72\x64\x20\x7a\x69\x6a\x6e" nocase fullword
    $wide = "\x62\x00\x65\x00\x73\x00\x6f\x00\x64\x00\x65\x00\x6d\x00\x69\x00\x65\x00\x74\x00\x65\x00\x72\x00\x64\x00\x20\x00\x7a\x00\x69\x00\x6a\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_16 {
  meta:
    info = "besodemieteren"
  strings:
    $utf8 = "\x62\x65\x73\x6f\x64\x65\x6d\x69\x65\x74\x65\x72\x65\x6e" nocase fullword
    $wide = "\x62\x00\x65\x00\x73\x00\x6f\x00\x64\x00\x65\x00\x6d\x00\x69\x00\x65\x00\x74\x00\x65\x00\x72\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_17 {
  meta:
    info = "boemelen"
  strings:
    $utf8 = "\x62\x6f\x65\x6d\x65\x6c\x65\x6e" nocase fullword
    $wide = "\x62\x00\x6f\x00\x65\x00\x6d\x00\x65\x00\x6c\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_18 {
  meta:
    info = "boerelul"
  strings:
    $utf8 = "\x62\x6f\x65\x72\x65\x6c\x75\x6c" nocase fullword
    $wide = "\x62\x00\x6f\x00\x65\x00\x72\x00\x65\x00\x6c\x00\x75\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_19 {
  meta:
    info = "boerenpummelg"
  strings:
    $utf8 = "\x62\x6f\x65\x72\x65\x6e\x70\x75\x6d\x6d\x65\x6c\x67" nocase fullword
    $wide = "\x62\x00\x6f\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x70\x00\x75\x00\x6d\x00\x6d\x00\x65\x00\x6c\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_20 {
  meta:
    info = "bokkelul"
  strings:
    $utf8 = "\x62\x6f\x6b\x6b\x65\x6c\x75\x6c" nocase fullword
    $wide = "\x62\x00\x6f\x00\x6b\x00\x6b\x00\x65\x00\x6c\x00\x75\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_21 {
  meta:
    info = "botergeil"
  strings:
    $utf8 = "\x62\x6f\x74\x65\x72\x67\x65\x69\x6c" nocase fullword
    $wide = "\x62\x00\x6f\x00\x74\x00\x65\x00\x72\x00\x67\x00\x65\x00\x69\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_22 {
  meta:
    info = "broekhoesten"
  strings:
    $utf8 = "\x62\x72\x6f\x65\x6b\x68\x6f\x65\x73\x74\x65\x6e" nocase fullword
    $wide = "\x62\x00\x72\x00\x6f\x00\x65\x00\x6b\x00\x68\x00\x6f\x00\x65\x00\x73\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_23 {
  meta:
    info = "brugpieperg"
  strings:
    $utf8 = "\x62\x72\x75\x67\x70\x69\x65\x70\x65\x72\x67" nocase fullword
    $wide = "\x62\x00\x72\x00\x75\x00\x67\x00\x70\x00\x69\x00\x65\x00\x70\x00\x65\x00\x72\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_24 {
  meta:
    info = "buffelen"
  strings:
    $utf8 = "\x62\x75\x66\x66\x65\x6c\x65\x6e" nocase fullword
    $wide = "\x62\x00\x75\x00\x66\x00\x66\x00\x65\x00\x6c\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_25 {
  meta:
    info = "buiten de pot piesen"
  strings:
    $utf8 = "\x62\x75\x69\x74\x65\x6e\x20\x64\x65\x20\x70\x6f\x74\x20\x70\x69\x65\x73\x65\x6e" nocase fullword
    $wide = "\x62\x00\x75\x00\x69\x00\x74\x00\x65\x00\x6e\x00\x20\x00\x64\x00\x65\x00\x20\x00\x70\x00\x6f\x00\x74\x00\x20\x00\x70\x00\x69\x00\x65\x00\x73\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_26 {
  meta:
    info = "da's kloten van de bok"
  strings:
    $utf8 = "\x64\x61\x27\x73\x20\x6b\x6c\x6f\x74\x65\x6e\x20\x76\x61\x6e\x20\x64\x65\x20\x62\x6f\x6b" nocase fullword
    $wide = "\x64\x00\x61\x00\x27\x00\x73\x00\x20\x00\x6b\x00\x6c\x00\x6f\x00\x74\x00\x65\x00\x6e\x00\x20\x00\x76\x00\x61\x00\x6e\x00\x20\x00\x64\x00\x65\x00\x20\x00\x62\x00\x6f\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_27 {
  meta:
    info = "de hoer spelen"
  strings:
    $utf8 = "\x64\x65\x20\x68\x6f\x65\x72\x20\x73\x70\x65\x6c\x65\x6e" nocase fullword
    $wide = "\x64\x00\x65\x00\x20\x00\x68\x00\x6f\x00\x65\x00\x72\x00\x20\x00\x73\x00\x70\x00\x65\x00\x6c\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_28 {
  meta:
    info = "de koffer induiken"
  strings:
    $utf8 = "\x64\x65\x20\x6b\x6f\x66\x66\x65\x72\x20\x69\x6e\x64\x75\x69\x6b\x65\x6e" nocase fullword
    $wide = "\x64\x00\x65\x00\x20\x00\x6b\x00\x6f\x00\x66\x00\x66\x00\x65\x00\x72\x00\x20\x00\x69\x00\x6e\x00\x64\x00\x75\x00\x69\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_29 {
  meta:
    info = "de pijp uitgaan"
  strings:
    $utf8 = "\x64\x65\x20\x70\x69\x6a\x70\x20\x75\x69\x74\x67\x61\x61\x6e" nocase fullword
    $wide = "\x64\x00\x65\x00\x20\x00\x70\x00\x69\x00\x6a\x00\x70\x00\x20\x00\x75\x00\x69\x00\x74\x00\x67\x00\x61\x00\x61\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_30 {
  meta:
    info = "delg"
  strings:
    $utf8 = "\x64\x65\x6c\x67" nocase fullword
    $wide = "\x64\x00\x65\x00\x6c\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_31 {
  meta:
    info = "dombo"
  strings:
    $utf8 = "\x64\x6f\x6d\x62\x6f" nocase fullword
    $wide = "\x64\x00\x6f\x00\x6d\x00\x62\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_32 {
  meta:
    info = "draaikontg"
  strings:
    $utf8 = "\x64\x72\x61\x61\x69\x6b\x6f\x6e\x74\x67" nocase fullword
    $wide = "\x64\x00\x72\x00\x61\x00\x61\x00\x69\x00\x6b\x00\x6f\x00\x6e\x00\x74\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_33 {
  meta:
    info = "driehoog achter wonen"
  strings:
    $utf8 = "\x64\x72\x69\x65\x68\x6f\x6f\x67\x20\x61\x63\x68\x74\x65\x72\x20\x77\x6f\x6e\x65\x6e" nocase fullword
    $wide = "\x64\x00\x72\x00\x69\x00\x65\x00\x68\x00\x6f\x00\x6f\x00\x67\x00\x20\x00\x61\x00\x63\x00\x68\x00\x74\x00\x65\x00\x72\x00\x20\x00\x77\x00\x6f\x00\x6e\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_34 {
  meta:
    info = "drolg"
  strings:
    $utf8 = "\x64\x72\x6f\x6c\x67" nocase fullword
    $wide = "\x64\x00\x72\x00\x6f\x00\x6c\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_35 {
  meta:
    info = "drooggeiler"
  strings:
    $utf8 = "\x64\x72\x6f\x6f\x67\x67\x65\x69\x6c\x65\x72" nocase fullword
    $wide = "\x64\x00\x72\x00\x6f\x00\x6f\x00\x67\x00\x67\x00\x65\x00\x69\x00\x6c\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_36 {
  meta:
    info = "droogkloot"
  strings:
    $utf8 = "\x64\x72\x6f\x6f\x67\x6b\x6c\x6f\x6f\x74" nocase fullword
    $wide = "\x64\x00\x72\x00\x6f\x00\x6f\x00\x67\x00\x6b\x00\x6c\x00\x6f\x00\x6f\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_37 {
  meta:
    info = "een nummertje maken"
  strings:
    $utf8 = "\x65\x65\x6e\x20\x6e\x75\x6d\x6d\x65\x72\x74\x6a\x65\x20\x6d\x61\x6b\x65\x6e" nocase fullword
    $wide = "\x65\x00\x65\x00\x6e\x00\x20\x00\x6e\x00\x75\x00\x6d\x00\x6d\x00\x65\x00\x72\x00\x74\x00\x6a\x00\x65\x00\x20\x00\x6d\x00\x61\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_38 {
  meta:
    info = "een wip maken"
  strings:
    $utf8 = "\x65\x65\x6e\x20\x77\x69\x70\x20\x6d\x61\x6b\x65\x6e" nocase fullword
    $wide = "\x65\x00\x65\x00\x6e\x00\x20\x00\x77\x00\x69\x00\x70\x00\x20\x00\x6d\x00\x61\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_39 {
  meta:
    info = "eikel"
  strings:
    $utf8 = "\x65\x69\x6b\x65\x6c" nocase fullword
    $wide = "\x65\x00\x69\x00\x6b\x00\x65\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_40 {
  meta:
    info = "engerd"
  strings:
    $utf8 = "\x65\x6e\x67\x65\x72\x64" nocase fullword
    $wide = "\x65\x00\x6e\x00\x67\x00\x65\x00\x72\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_41 {
  meta:
    info = "flamoes"
  strings:
    $utf8 = "\x66\x6c\x61\x6d\x6f\x65\x73" nocase fullword
    $wide = "\x66\x00\x6c\x00\x61\x00\x6d\x00\x6f\x00\x65\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_42 {
  meta:
    info = "flikken"
  strings:
    $utf8 = "\x66\x6c\x69\x6b\x6b\x65\x6e" nocase fullword
    $wide = "\x66\x00\x6c\x00\x69\x00\x6b\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_43 {
  meta:
    info = "flikker"
  strings:
    $utf8 = "\x66\x6c\x69\x6b\x6b\x65\x72" nocase fullword
    $wide = "\x66\x00\x6c\x00\x69\x00\x6b\x00\x6b\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_44 {
  meta:
    info = "gadverdamme"
  strings:
    $utf8 = "\x67\x61\x64\x76\x65\x72\x64\x61\x6d\x6d\x65" nocase fullword
    $wide = "\x67\x00\x61\x00\x64\x00\x76\x00\x65\x00\x72\x00\x64\x00\x61\x00\x6d\x00\x6d\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_45 {
  meta:
    info = "galbak"
  strings:
    $utf8 = "\x67\x61\x6c\x62\x61\x6b" nocase fullword
    $wide = "\x67\x00\x61\x00\x6c\x00\x62\x00\x61\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_46 {
  meta:
    info = "geilneef"
  strings:
    $utf8 = "\x67\x65\x69\x6c\x6e\x65\x65\x66" nocase fullword
    $wide = "\x67\x00\x65\x00\x69\x00\x6c\x00\x6e\x00\x65\x00\x65\x00\x66\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_47 {
  meta:
    info = "gesodemieter"
  strings:
    $utf8 = "\x67\x65\x73\x6f\x64\x65\x6d\x69\x65\x74\x65\x72" nocase fullword
    $wide = "\x67\x00\x65\x00\x73\x00\x6f\x00\x64\x00\x65\x00\x6d\x00\x69\x00\x65\x00\x74\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_48 {
  meta:
    info = "godverdomme"
  strings:
    $utf8 = "\x67\x6f\x64\x76\x65\x72\x64\x6f\x6d\x6d\x65" nocase fullword
    $wide = "\x67\x00\x6f\x00\x64\x00\x76\x00\x65\x00\x72\x00\x64\x00\x6f\x00\x6d\x00\x6d\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_49 {
  meta:
    info = "graftak"
  strings:
    $utf8 = "\x67\x72\x61\x66\x74\x61\x6b" nocase fullword
    $wide = "\x67\x00\x72\x00\x61\x00\x66\x00\x74\x00\x61\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_50 {
  meta:
    info = "gras maaien"
  strings:
    $utf8 = "\x67\x72\x61\x73\x20\x6d\x61\x61\x69\x65\x6e" nocase fullword
    $wide = "\x67\x00\x72\x00\x61\x00\x73\x00\x20\x00\x6d\x00\x61\x00\x61\x00\x69\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_51 {
  meta:
    info = "gratenkutg"
  strings:
    $utf8 = "\x67\x72\x61\x74\x65\x6e\x6b\x75\x74\x67" nocase fullword
    $wide = "\x67\x00\x72\x00\x61\x00\x74\x00\x65\x00\x6e\x00\x6b\x00\x75\x00\x74\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_52 {
  meta:
    info = "greppeldel"
  strings:
    $utf8 = "\x67\x72\x65\x70\x70\x65\x6c\x64\x65\x6c" nocase fullword
    $wide = "\x67\x00\x72\x00\x65\x00\x70\x00\x70\x00\x65\x00\x6c\x00\x64\x00\x65\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_53 {
  meta:
    info = "griet"
  strings:
    $utf8 = "\x67\x72\x69\x65\x74" nocase fullword
    $wide = "\x67\x00\x72\x00\x69\x00\x65\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_54 {
  meta:
    info = "hoempert"
  strings:
    $utf8 = "\x68\x6f\x65\x6d\x70\x65\x72\x74" nocase fullword
    $wide = "\x68\x00\x6f\x00\x65\x00\x6d\x00\x70\x00\x65\x00\x72\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_55 {
  meta:
    info = "hoer"
  strings:
    $utf8 = "\x68\x6f\x65\x72" nocase fullword
    $wide = "\x68\x00\x6f\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_56 {
  meta:
    info = "hoerenbuurt"
  strings:
    $utf8 = "\x68\x6f\x65\x72\x65\x6e\x62\x75\x75\x72\x74" nocase fullword
    $wide = "\x68\x00\x6f\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x62\x00\x75\x00\x75\x00\x72\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_57 {
  meta:
    info = "hoerenloper"
  strings:
    $utf8 = "\x68\x6f\x65\x72\x65\x6e\x6c\x6f\x70\x65\x72" nocase fullword
    $wide = "\x68\x00\x6f\x00\x65\x00\x72\x00\x65\x00\x6e\x00\x6c\x00\x6f\x00\x70\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_58 {
  meta:
    info = "hoerig"
  strings:
    $utf8 = "\x68\x6f\x65\x72\x69\x67" nocase fullword
    $wide = "\x68\x00\x6f\x00\x65\x00\x72\x00\x69\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_59 {
  meta:
    info = "hol"
  strings:
    $utf8 = "\x68\x6f\x6c" nocase fullword
    $wide = "\x68\x00\x6f\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_60 {
  meta:
    info = "hufter"
  strings:
    $utf8 = "\x68\x75\x66\x74\x65\x72" nocase fullword
    $wide = "\x68\x00\x75\x00\x66\x00\x74\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_61 {
  meta:
    info = "huisdealer"
  strings:
    $utf8 = "\x68\x75\x69\x73\x64\x65\x61\x6c\x65\x72" nocase fullword
    $wide = "\x68\x00\x75\x00\x69\x00\x73\x00\x64\x00\x65\x00\x61\x00\x6c\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_62 {
  meta:
    info = "kanen"
  strings:
    $utf8 = "\x6b\x61\x6e\x65\x6e" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6e\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_63 {
  meta:
    info = "kettingzeugg"
  strings:
    $utf8 = "\x6b\x65\x74\x74\x69\x6e\x67\x7a\x65\x75\x67\x67" nocase fullword
    $wide = "\x6b\x00\x65\x00\x74\x00\x74\x00\x69\x00\x6e\x00\x67\x00\x7a\x00\x65\x00\x75\x00\x67\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_64 {
  meta:
    info = "klaarkomen"
  strings:
    $utf8 = "\x6b\x6c\x61\x61\x72\x6b\x6f\x6d\x65\x6e" nocase fullword
    $wide = "\x6b\x00\x6c\x00\x61\x00\x61\x00\x72\x00\x6b\x00\x6f\x00\x6d\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_65 {
  meta:
    info = "klerebeer"
  strings:
    $utf8 = "\x6b\x6c\x65\x72\x65\x62\x65\x65\x72" nocase fullword
    $wide = "\x6b\x00\x6c\x00\x65\x00\x72\x00\x65\x00\x62\x00\x65\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_66 {
  meta:
    info = "klojo"
  strings:
    $utf8 = "\x6b\x6c\x6f\x6a\x6f" nocase fullword
    $wide = "\x6b\x00\x6c\x00\x6f\x00\x6a\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_67 {
  meta:
    info = "klooien"
  strings:
    $utf8 = "\x6b\x6c\x6f\x6f\x69\x65\x6e" nocase fullword
    $wide = "\x6b\x00\x6c\x00\x6f\x00\x6f\x00\x69\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_68 {
  meta:
    info = "klootjesvolk"
  strings:
    $utf8 = "\x6b\x6c\x6f\x6f\x74\x6a\x65\x73\x76\x6f\x6c\x6b" nocase fullword
    $wide = "\x6b\x00\x6c\x00\x6f\x00\x6f\x00\x74\x00\x6a\x00\x65\x00\x73\x00\x76\x00\x6f\x00\x6c\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_69 {
  meta:
    info = "klootoog"
  strings:
    $utf8 = "\x6b\x6c\x6f\x6f\x74\x6f\x6f\x67" nocase fullword
    $wide = "\x6b\x00\x6c\x00\x6f\x00\x6f\x00\x74\x00\x6f\x00\x6f\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_70 {
  meta:
    info = "klootzak"
  strings:
    $utf8 = "\x6b\x6c\x6f\x6f\x74\x7a\x61\x6b" nocase fullword
    $wide = "\x6b\x00\x6c\x00\x6f\x00\x6f\x00\x74\x00\x7a\x00\x61\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_71 {
  meta:
    info = "kloten"
  strings:
    $utf8 = "\x6b\x6c\x6f\x74\x65\x6e" nocase fullword
    $wide = "\x6b\x00\x6c\x00\x6f\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_72 {
  meta:
    info = "knor"
  strings:
    $utf8 = "\x6b\x6e\x6f\x72" nocase fullword
    $wide = "\x6b\x00\x6e\x00\x6f\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_73 {
  meta:
    info = "kontg"
  strings:
    $utf8 = "\x6b\x6f\x6e\x74\x67" nocase fullword
    $wide = "\x6b\x00\x6f\x00\x6e\x00\x74\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_74 {
  meta:
    info = "kontneuken"
  strings:
    $utf8 = "\x6b\x6f\x6e\x74\x6e\x65\x75\x6b\x65\x6e" nocase fullword
    $wide = "\x6b\x00\x6f\x00\x6e\x00\x74\x00\x6e\x00\x65\x00\x75\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_75 {
  meta:
    info = "krentekakker"
  strings:
    $utf8 = "\x6b\x72\x65\x6e\x74\x65\x6b\x61\x6b\x6b\x65\x72" nocase fullword
    $wide = "\x6b\x00\x72\x00\x65\x00\x6e\x00\x74\x00\x65\x00\x6b\x00\x61\x00\x6b\x00\x6b\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_76 {
  meta:
    info = "kut"
  strings:
    $utf8 = "\x6b\x75\x74" nocase fullword
    $wide = "\x6b\x00\x75\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_77 {
  meta:
    info = "kuttelikkertje"
  strings:
    $utf8 = "\x6b\x75\x74\x74\x65\x6c\x69\x6b\x6b\x65\x72\x74\x6a\x65" nocase fullword
    $wide = "\x6b\x00\x75\x00\x74\x00\x74\x00\x65\x00\x6c\x00\x69\x00\x6b\x00\x6b\x00\x65\x00\x72\x00\x74\x00\x6a\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_78 {
  meta:
    info = "kwakkieg"
  strings:
    $utf8 = "\x6b\x77\x61\x6b\x6b\x69\x65\x67" nocase fullword
    $wide = "\x6b\x00\x77\x00\x61\x00\x6b\x00\x6b\x00\x69\x00\x65\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_79 {
  meta:
    info = "liefdesgrot"
  strings:
    $utf8 = "\x6c\x69\x65\x66\x64\x65\x73\x67\x72\x6f\x74" nocase fullword
    $wide = "\x6c\x00\x69\x00\x65\x00\x66\x00\x64\x00\x65\x00\x73\x00\x67\x00\x72\x00\x6f\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_80 {
  meta:
    info = "lul"
  strings:
    $utf8 = "\x6c\x75\x6c" nocase fullword
    $wide = "\x6c\x00\x75\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_81 {
  meta:
    info = "lul-de-behanger"
  strings:
    $utf8 = "\x6c\x75\x6c\x2d\x64\x65\x2d\x62\x65\x68\x61\x6e\x67\x65\x72" nocase fullword
    $wide = "\x6c\x00\x75\x00\x6c\x00\x2d\x00\x64\x00\x65\x00\x2d\x00\x62\x00\x65\x00\x68\x00\x61\x00\x6e\x00\x67\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_82 {
  meta:
    info = "lulhannes"
  strings:
    $utf8 = "\x6c\x75\x6c\x68\x61\x6e\x6e\x65\x73" nocase fullword
    $wide = "\x6c\x00\x75\x00\x6c\x00\x68\x00\x61\x00\x6e\x00\x6e\x00\x65\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_83 {
  meta:
    info = "lummel"
  strings:
    $utf8 = "\x6c\x75\x6d\x6d\x65\x6c" nocase fullword
    $wide = "\x6c\x00\x75\x00\x6d\x00\x6d\x00\x65\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_84 {
  meta:
    info = "mafketel"
  strings:
    $utf8 = "\x6d\x61\x66\x6b\x65\x74\x65\x6c" nocase fullword
    $wide = "\x6d\x00\x61\x00\x66\x00\x6b\x00\x65\x00\x74\x00\x65\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_85 {
  meta:
    info = "matennaaierg"
  strings:
    $utf8 = "\x6d\x61\x74\x65\x6e\x6e\x61\x61\x69\x65\x72\x67" nocase fullword
    $wide = "\x6d\x00\x61\x00\x74\x00\x65\x00\x6e\x00\x6e\x00\x61\x00\x61\x00\x69\x00\x65\x00\x72\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_86 {
  meta:
    info = "matje"
  strings:
    $utf8 = "\x6d\x61\x74\x6a\x65" nocase fullword
    $wide = "\x6d\x00\x61\x00\x74\x00\x6a\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_87 {
  meta:
    info = "mof"
  strings:
    $utf8 = "\x6d\x6f\x66" nocase fullword
    $wide = "\x6d\x00\x6f\x00\x66\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_88 {
  meta:
    info = "mutsg"
  strings:
    $utf8 = "\x6d\x75\x74\x73\x67" nocase fullword
    $wide = "\x6d\x00\x75\x00\x74\x00\x73\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_89 {
  meta:
    info = "naaien"
  strings:
    $utf8 = "\x6e\x61\x61\x69\x65\x6e" nocase fullword
    $wide = "\x6e\x00\x61\x00\x61\x00\x69\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_90 {
  meta:
    info = "naakt"
  strings:
    $utf8 = "\x6e\x61\x61\x6b\x74" nocase fullword
    $wide = "\x6e\x00\x61\x00\x61\x00\x6b\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_91 {
  meta:
    info = "neuken"
  strings:
    $utf8 = "\x6e\x65\x75\x6b\x65\x6e" nocase fullword
    $wide = "\x6e\x00\x65\x00\x75\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_92 {
  meta:
    info = "neukstier"
  strings:
    $utf8 = "\x6e\x65\x75\x6b\x73\x74\x69\x65\x72" nocase fullword
    $wide = "\x6e\x00\x65\x00\x75\x00\x6b\x00\x73\x00\x74\x00\x69\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_93 {
  meta:
    info = "nicht"
  strings:
    $utf8 = "\x6e\x69\x63\x68\x74" nocase fullword
    $wide = "\x6e\x00\x69\x00\x63\x00\x68\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_94 {
  meta:
    info = "oetlul"
  strings:
    $utf8 = "\x6f\x65\x74\x6c\x75\x6c" nocase fullword
    $wide = "\x6f\x00\x65\x00\x74\x00\x6c\x00\x75\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_95 {
  meta:
    info = "op z'n hondjes"
  strings:
    $utf8 = "\x6f\x70\x20\x7a\x27\x6e\x20\x68\x6f\x6e\x64\x6a\x65\x73" nocase fullword
    $wide = "\x6f\x00\x70\x00\x20\x00\x7a\x00\x27\x00\x6e\x00\x20\x00\x68\x00\x6f\x00\x6e\x00\x64\x00\x6a\x00\x65\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_96 {
  meta:
    info = "op z'n sodemieter geven"
  strings:
    $utf8 = "\x6f\x70\x20\x7a\x27\x6e\x20\x73\x6f\x64\x65\x6d\x69\x65\x74\x65\x72\x20\x67\x65\x76\x65\x6e" nocase fullword
    $wide = "\x6f\x00\x70\x00\x20\x00\x7a\x00\x27\x00\x6e\x00\x20\x00\x73\x00\x6f\x00\x64\x00\x65\x00\x6d\x00\x69\x00\x65\x00\x74\x00\x65\x00\x72\x00\x20\x00\x67\x00\x65\x00\x76\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_97 {
  meta:
    info = "opgeilen"
  strings:
    $utf8 = "\x6f\x70\x67\x65\x69\x6c\x65\x6e" nocase fullword
    $wide = "\x6f\x00\x70\x00\x67\x00\x65\x00\x69\x00\x6c\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_98 {
  meta:
    info = "opkankeren"
  strings:
    $utf8 = "\x6f\x70\x6b\x61\x6e\x6b\x65\x72\x65\x6e" nocase fullword
    $wide = "\x6f\x00\x70\x00\x6b\x00\x61\x00\x6e\x00\x6b\x00\x65\x00\x72\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_99 {
  meta:
    info = "oprotten"
  strings:
    $utf8 = "\x6f\x70\x72\x6f\x74\x74\x65\x6e" nocase fullword
    $wide = "\x6f\x00\x70\x00\x72\x00\x6f\x00\x74\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_100 {
  meta:
    info = "opsodemieteren"
  strings:
    $utf8 = "\x6f\x70\x73\x6f\x64\x65\x6d\x69\x65\x74\x65\x72\x65\x6e" nocase fullword
    $wide = "\x6f\x00\x70\x00\x73\x00\x6f\x00\x64\x00\x65\x00\x6d\x00\x69\x00\x65\x00\x74\x00\x65\x00\x72\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_101 {
  meta:
    info = "opzouten"
  strings:
    $utf8 = "\x6f\x70\x7a\x6f\x75\x74\x65\x6e" nocase fullword
    $wide = "\x6f\x00\x70\x00\x7a\x00\x6f\x00\x75\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_102 {
  meta:
    info = "ouwe rukker"
  strings:
    $utf8 = "\x6f\x75\x77\x65\x20\x72\x75\x6b\x6b\x65\x72" nocase fullword
    $wide = "\x6f\x00\x75\x00\x77\x00\x65\x00\x20\x00\x72\x00\x75\x00\x6b\x00\x6b\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_103 {
  meta:
    info = "ouwehoer"
  strings:
    $utf8 = "\x6f\x75\x77\x65\x68\x6f\x65\x72" nocase fullword
    $wide = "\x6f\x00\x75\x00\x77\x00\x65\x00\x68\x00\x6f\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_104 {
  meta:
    info = "ouwehoeren"
  strings:
    $utf8 = "\x6f\x75\x77\x65\x68\x6f\x65\x72\x65\x6e" nocase fullword
    $wide = "\x6f\x00\x75\x00\x77\x00\x65\x00\x68\x00\x6f\x00\x65\x00\x72\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_105 {
  meta:
    info = "paardelul"
  strings:
    $utf8 = "\x70\x61\x61\x72\x64\x65\x6c\x75\x6c" nocase fullword
    $wide = "\x70\x00\x61\x00\x61\x00\x72\x00\x64\x00\x65\x00\x6c\x00\x75\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_106 {
  meta:
    info = "palen"
  strings:
    $utf8 = "\x70\x61\x6c\x65\x6e" nocase fullword
    $wide = "\x70\x00\x61\x00\x6c\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_107 {
  meta:
    info = "penozeg"
  strings:
    $utf8 = "\x70\x65\x6e\x6f\x7a\x65\x67" nocase fullword
    $wide = "\x70\x00\x65\x00\x6e\x00\x6f\x00\x7a\x00\x65\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_108 {
  meta:
    info = "piesen"
  strings:
    $utf8 = "\x70\x69\x65\x73\x65\x6e" nocase fullword
    $wide = "\x70\x00\x69\x00\x65\x00\x73\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_109 {
  meta:
    info = "pijpbekkieg"
  strings:
    $utf8 = "\x70\x69\x6a\x70\x62\x65\x6b\x6b\x69\x65\x67" nocase fullword
    $wide = "\x70\x00\x69\x00\x6a\x00\x70\x00\x62\x00\x65\x00\x6b\x00\x6b\x00\x69\x00\x65\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_110 {
  meta:
    info = "pijpen"
  strings:
    $utf8 = "\x70\x69\x6a\x70\x65\x6e" nocase fullword
    $wide = "\x70\x00\x69\x00\x6a\x00\x70\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_111 {
  meta:
    info = "pik"
  strings:
    $utf8 = "\x70\x69\x6b" nocase fullword
    $wide = "\x70\x00\x69\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_112 {
  meta:
    info = "pleurislaaier"
  strings:
    $utf8 = "\x70\x6c\x65\x75\x72\x69\x73\x6c\x61\x61\x69\x65\x72" nocase fullword
    $wide = "\x70\x00\x6c\x00\x65\x00\x75\x00\x72\x00\x69\x00\x73\x00\x6c\x00\x61\x00\x61\x00\x69\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_113 {
  meta:
    info = "poep"
  strings:
    $utf8 = "\x70\x6f\x65\x70" nocase fullword
    $wide = "\x70\x00\x6f\x00\x65\x00\x70\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_114 {
  meta:
    info = "poepen"
  strings:
    $utf8 = "\x70\x6f\x65\x70\x65\x6e" nocase fullword
    $wide = "\x70\x00\x6f\x00\x65\x00\x70\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_115 {
  meta:
    info = "poot"
  strings:
    $utf8 = "\x70\x6f\x6f\x74" nocase fullword
    $wide = "\x70\x00\x6f\x00\x6f\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_116 {
  meta:
    info = "portiekslet"
  strings:
    $utf8 = "\x70\x6f\x72\x74\x69\x65\x6b\x73\x6c\x65\x74" nocase fullword
    $wide = "\x70\x00\x6f\x00\x72\x00\x74\x00\x69\x00\x65\x00\x6b\x00\x73\x00\x6c\x00\x65\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_117 {
  meta:
    info = "potverdorie"
  strings:
    $utf8 = "\x70\x6f\x74\x76\x65\x72\x64\x6f\x72\x69\x65" nocase fullword
    $wide = "\x70\x00\x6f\x00\x74\x00\x76\x00\x65\x00\x72\x00\x64\x00\x6f\x00\x72\x00\x69\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_118 {
  meta:
    info = "publiciteitsgeil"
  strings:
    $utf8 = "\x70\x75\x62\x6c\x69\x63\x69\x74\x65\x69\x74\x73\x67\x65\x69\x6c" nocase fullword
    $wide = "\x70\x00\x75\x00\x62\x00\x6c\x00\x69\x00\x63\x00\x69\x00\x74\x00\x65\x00\x69\x00\x74\x00\x73\x00\x67\x00\x65\x00\x69\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_119 {
  meta:
    info = "raaskallen"
  strings:
    $utf8 = "\x72\x61\x61\x73\x6b\x61\x6c\x6c\x65\x6e" nocase fullword
    $wide = "\x72\x00\x61\x00\x61\x00\x73\x00\x6b\x00\x61\x00\x6c\x00\x6c\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_120 {
  meta:
    info = "reet"
  strings:
    $utf8 = "\x72\x65\x65\x74" nocase fullword
    $wide = "\x72\x00\x65\x00\x65\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_121 {
  meta:
    info = "reet trappen, voor zijn"
  strings:
    $utf8 = "\x72\x65\x65\x74\x20\x74\x72\x61\x70\x70\x65\x6e\x2c\x20\x76\x6f\x6f\x72\x20\x7a\x69\x6a\x6e" nocase fullword
    $wide = "\x72\x00\x65\x00\x65\x00\x74\x00\x20\x00\x74\x00\x72\x00\x61\x00\x70\x00\x70\x00\x65\x00\x6e\x00\x2c\x00\x20\x00\x76\x00\x6f\x00\x6f\x00\x72\x00\x20\x00\x7a\x00\x69\x00\x6a\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_122 {
  meta:
    info = "reetridder"
  strings:
    $utf8 = "\x72\x65\x65\x74\x72\x69\x64\x64\x65\x72" nocase fullword
    $wide = "\x72\x00\x65\x00\x65\x00\x74\x00\x72\x00\x69\x00\x64\x00\x64\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_123 {
  meta:
    info = "remsporeng"
  strings:
    $utf8 = "\x72\x65\x6d\x73\x70\x6f\x72\x65\x6e\x67" nocase fullword
    $wide = "\x72\x00\x65\x00\x6d\x00\x73\x00\x70\x00\x6f\x00\x72\x00\x65\x00\x6e\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_124 {
  meta:
    info = "reutelen"
  strings:
    $utf8 = "\x72\x65\x75\x74\x65\x6c\x65\x6e" nocase fullword
    $wide = "\x72\x00\x65\x00\x75\x00\x74\x00\x65\x00\x6c\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_125 {
  meta:
    info = "rothoer"
  strings:
    $utf8 = "\x72\x6f\x74\x68\x6f\x65\x72" nocase fullword
    $wide = "\x72\x00\x6f\x00\x74\x00\x68\x00\x6f\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_126 {
  meta:
    info = "rotzak"
  strings:
    $utf8 = "\x72\x6f\x74\x7a\x61\x6b" nocase fullword
    $wide = "\x72\x00\x6f\x00\x74\x00\x7a\x00\x61\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_127 {
  meta:
    info = "rukhond"
  strings:
    $utf8 = "\x72\x75\x6b\x68\x6f\x6e\x64" nocase fullword
    $wide = "\x72\x00\x75\x00\x6b\x00\x68\x00\x6f\x00\x6e\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_128 {
  meta:
    info = "rukken"
  strings:
    $utf8 = "\x72\x75\x6b\x6b\x65\x6e" nocase fullword
    $wide = "\x72\x00\x75\x00\x6b\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_129 {
  meta:
    info = "schatje"
  strings:
    $utf8 = "\x73\x63\x68\x61\x74\x6a\x65" nocase fullword
    $wide = "\x73\x00\x63\x00\x68\x00\x61\x00\x74\x00\x6a\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_130 {
  meta:
    info = "schijt"
  strings:
    $utf8 = "\x73\x63\x68\x69\x6a\x74" nocase fullword
    $wide = "\x73\x00\x63\x00\x68\x00\x69\x00\x6a\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_131 {
  meta:
    info = "schijten"
  strings:
    $utf8 = "\x73\x63\x68\x69\x6a\x74\x65\x6e" nocase fullword
    $wide = "\x73\x00\x63\x00\x68\x00\x69\x00\x6a\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_132 {
  meta:
    info = "schoft"
  strings:
    $utf8 = "\x73\x63\x68\x6f\x66\x74" nocase fullword
    $wide = "\x73\x00\x63\x00\x68\x00\x6f\x00\x66\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_133 {
  meta:
    info = "schuinsmarcheerder"
  strings:
    $utf8 = "\x73\x63\x68\x75\x69\x6e\x73\x6d\x61\x72\x63\x68\x65\x65\x72\x64\x65\x72" nocase fullword
    $wide = "\x73\x00\x63\x00\x68\x00\x75\x00\x69\x00\x6e\x00\x73\x00\x6d\x00\x61\x00\x72\x00\x63\x00\x68\x00\x65\x00\x65\x00\x72\x00\x64\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_134 {
  meta:
    info = "shit"
  strings:
    $utf8 = "\x73\x68\x69\x74" nocase fullword
    $wide = "\x73\x00\x68\x00\x69\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_135 {
  meta:
    info = "slempen"
  strings:
    $utf8 = "\x73\x6c\x65\x6d\x70\x65\x6e" nocase fullword
    $wide = "\x73\x00\x6c\x00\x65\x00\x6d\x00\x70\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_136 {
  meta:
    info = "sletg"
  strings:
    $utf8 = "\x73\x6c\x65\x74\x67" nocase fullword
    $wide = "\x73\x00\x6c\x00\x65\x00\x74\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_137 {
  meta:
    info = "sletterig"
  strings:
    $utf8 = "\x73\x6c\x65\x74\x74\x65\x72\x69\x67" nocase fullword
    $wide = "\x73\x00\x6c\x00\x65\x00\x74\x00\x74\x00\x65\x00\x72\x00\x69\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_138 {
  meta:
    info = "slik mijn zaad"
  strings:
    $utf8 = "\x73\x6c\x69\x6b\x20\x6d\x69\x6a\x6e\x20\x7a\x61\x61\x64" nocase fullword
    $wide = "\x73\x00\x6c\x00\x69\x00\x6b\x00\x20\x00\x6d\x00\x69\x00\x6a\x00\x6e\x00\x20\x00\x7a\x00\x61\x00\x61\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_139 {
  meta:
    info = "snolg"
  strings:
    $utf8 = "\x73\x6e\x6f\x6c\x67" nocase fullword
    $wide = "\x73\x00\x6e\x00\x6f\x00\x6c\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_140 {
  meta:
    info = "spuiten"
  strings:
    $utf8 = "\x73\x70\x75\x69\x74\x65\x6e" nocase fullword
    $wide = "\x73\x00\x70\x00\x75\x00\x69\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_141 {
  meta:
    info = "standje"
  strings:
    $utf8 = "\x73\x74\x61\x6e\x64\x6a\x65" nocase fullword
    $wide = "\x73\x00\x74\x00\x61\x00\x6e\x00\x64\x00\x6a\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_142 {
  meta:
    info = "standje-69g"
  strings:
    $utf8 = "\x73\x74\x61\x6e\x64\x6a\x65\x2d\x36\x39\x67" nocase fullword
    $wide = "\x73\x00\x74\x00\x61\x00\x6e\x00\x64\x00\x6a\x00\x65\x00\x2d\x00\x36\x00\x39\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_143 {
  meta:
    info = "stoephoer"
  strings:
    $utf8 = "\x73\x74\x6f\x65\x70\x68\x6f\x65\x72" nocase fullword
    $wide = "\x73\x00\x74\x00\x6f\x00\x65\x00\x70\x00\x68\x00\x6f\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_144 {
  meta:
    info = "strontg"
  strings:
    $utf8 = "\x73\x74\x72\x6f\x6e\x74\x67" nocase fullword
    $wide = "\x73\x00\x74\x00\x72\x00\x6f\x00\x6e\x00\x74\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_145 {
  meta:
    info = "sufferdg"
  strings:
    $utf8 = "\x73\x75\x66\x66\x65\x72\x64\x67" nocase fullword
    $wide = "\x73\x00\x75\x00\x66\x00\x66\x00\x65\x00\x72\x00\x64\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_146 {
  meta:
    info = "tapijtnek"
  strings:
    $utf8 = "\x74\x61\x70\x69\x6a\x74\x6e\x65\x6b" nocase fullword
    $wide = "\x74\x00\x61\x00\x70\x00\x69\x00\x6a\x00\x74\x00\x6e\x00\x65\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_147 {
  meta:
    info = "teefg"
  strings:
    $utf8 = "\x74\x65\x65\x66\x67" nocase fullword
    $wide = "\x74\x00\x65\x00\x65\x00\x66\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_148 {
  meta:
    info = "temeier"
  strings:
    $utf8 = "\x74\x65\x6d\x65\x69\x65\x72" nocase fullword
    $wide = "\x74\x00\x65\x00\x6d\x00\x65\x00\x69\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_149 {
  meta:
    info = "teringlijer"
  strings:
    $utf8 = "\x74\x65\x72\x69\x6e\x67\x6c\x69\x6a\x65\x72" nocase fullword
    $wide = "\x74\x00\x65\x00\x72\x00\x69\x00\x6e\x00\x67\x00\x6c\x00\x69\x00\x6a\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_150 {
  meta:
    info = "toeter"
  strings:
    $utf8 = "\x74\x6f\x65\x74\x65\x72" nocase fullword
    $wide = "\x74\x00\x6f\x00\x65\x00\x74\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_151 {
  meta:
    info = "tongzoeng"
  strings:
    $utf8 = "\x74\x6f\x6e\x67\x7a\x6f\x65\x6e\x67" nocase fullword
    $wide = "\x74\x00\x6f\x00\x6e\x00\x67\x00\x7a\x00\x6f\x00\x65\x00\x6e\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_152 {
  meta:
    info = "triootjeg"
  strings:
    $utf8 = "\x74\x72\x69\x6f\x6f\x74\x6a\x65\x67" nocase fullword
    $wide = "\x74\x00\x72\x00\x69\x00\x6f\x00\x6f\x00\x74\x00\x6a\x00\x65\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_153 {
  meta:
    info = "trottoir prostituée"
  strings:
    $utf8 = "\x74\x72\x6f\x74\x74\x6f\x69\x72\x20\x70\x72\x6f\x73\x74\x69\x74\x75\xc3\xa9\x65" nocase fullword
    $wide = "\x74\x00\x72\x00\x6f\x00\x74\x00\x74\x00\x6f\x00\x69\x00\x72\x00\x20\x00\x70\x00\x72\x00\x6f\x00\x73\x00\x74\x00\x69\x00\x74\x00\x75\x00\xe9\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_154 {
  meta:
    info = "trottoirteef"
  strings:
    $utf8 = "\x74\x72\x6f\x74\x74\x6f\x69\x72\x74\x65\x65\x66" nocase fullword
    $wide = "\x74\x00\x72\x00\x6f\x00\x74\x00\x74\x00\x6f\x00\x69\x00\x72\x00\x74\x00\x65\x00\x65\x00\x66\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_155 {
  meta:
    info = "verkloten"
  strings:
    $utf8 = "\x76\x65\x72\x6b\x6c\x6f\x74\x65\x6e" nocase fullword
    $wide = "\x76\x00\x65\x00\x72\x00\x6b\x00\x6c\x00\x6f\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_156 {
  meta:
    info = "verneuken"
  strings:
    $utf8 = "\x76\x65\x72\x6e\x65\x75\x6b\x65\x6e" nocase fullword
    $wide = "\x76\x00\x65\x00\x72\x00\x6e\x00\x65\x00\x75\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_157 {
  meta:
    info = "viespeuk"
  strings:
    $utf8 = "\x76\x69\x65\x73\x70\x65\x75\x6b" nocase fullword
    $wide = "\x76\x00\x69\x00\x65\x00\x73\x00\x70\x00\x65\x00\x75\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_158 {
  meta:
    info = "vingeren"
  strings:
    $utf8 = "\x76\x69\x6e\x67\x65\x72\x65\x6e" nocase fullword
    $wide = "\x76\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x72\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_159 {
  meta:
    info = "voor jan lul"
  strings:
    $utf8 = "\x76\x6f\x6f\x72\x20\x6a\x61\x6e\x20\x6c\x75\x6c" nocase fullword
    $wide = "\x76\x00\x6f\x00\x6f\x00\x72\x00\x20\x00\x6a\x00\x61\x00\x6e\x00\x20\x00\x6c\x00\x75\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_160 {
  meta:
    info = "voor jan-met-de-korte-achternaam"
  strings:
    $utf8 = "\x76\x6f\x6f\x72\x20\x6a\x61\x6e\x2d\x6d\x65\x74\x2d\x64\x65\x2d\x6b\x6f\x72\x74\x65\x2d\x61\x63\x68\x74\x65\x72\x6e\x61\x61\x6d" nocase fullword
    $wide = "\x76\x00\x6f\x00\x6f\x00\x72\x00\x20\x00\x6a\x00\x61\x00\x6e\x00\x2d\x00\x6d\x00\x65\x00\x74\x00\x2d\x00\x64\x00\x65\x00\x2d\x00\x6b\x00\x6f\x00\x72\x00\x74\x00\x65\x00\x2d\x00\x61\x00\x63\x00\x68\x00\x74\x00\x65\x00\x72\x00\x6e\x00\x61\x00\x61\x00\x6d\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_161 {
  meta:
    info = "watje"
  strings:
    $utf8 = "\x77\x61\x74\x6a\x65" nocase fullword
    $wide = "\x77\x00\x61\x00\x74\x00\x6a\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_162 {
  meta:
    info = "welzijnsmafia"
  strings:
    $utf8 = "\x77\x65\x6c\x7a\x69\x6a\x6e\x73\x6d\x61\x66\x69\x61" nocase fullword
    $wide = "\x77\x00\x65\x00\x6c\x00\x7a\x00\x69\x00\x6a\x00\x6e\x00\x73\x00\x6d\x00\x61\x00\x66\x00\x69\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_163 {
  meta:
    info = "wijf"
  strings:
    $utf8 = "\x77\x69\x6a\x66" nocase fullword
    $wide = "\x77\x00\x69\x00\x6a\x00\x66\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_164 {
  meta:
    info = "wippen"
  strings:
    $utf8 = "\x77\x69\x70\x70\x65\x6e" nocase fullword
    $wide = "\x77\x00\x69\x00\x70\x00\x70\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_165 {
  meta:
    info = "wuftje"
  strings:
    $utf8 = "\x77\x75\x66\x74\x6a\x65" nocase fullword
    $wide = "\x77\x00\x75\x00\x66\x00\x74\x00\x6a\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_166 {
  meta:
    info = "zakkenwasser"
  strings:
    $utf8 = "\x7a\x61\x6b\x6b\x65\x6e\x77\x61\x73\x73\x65\x72" nocase fullword
    $wide = "\x7a\x00\x61\x00\x6b\x00\x6b\x00\x65\x00\x6e\x00\x77\x00\x61\x00\x73\x00\x73\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_167 {
  meta:
    info = "zeiken"
  strings:
    $utf8 = "\x7a\x65\x69\x6b\x65\x6e" nocase fullword
    $wide = "\x7a\x00\x65\x00\x69\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_168 {
  meta:
    info = "zeiker"
  strings:
    $utf8 = "\x7a\x65\x69\x6b\x65\x72" nocase fullword
    $wide = "\x7a\x00\x65\x00\x69\x00\x6b\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_nl_language_nsfw_169 {
  meta:
    info = "zuiplap"
  strings:
    $utf8 = "\x7a\x75\x69\x70\x6c\x61\x70" nocase fullword
    $wide = "\x7a\x00\x75\x00\x69\x00\x70\x00\x6c\x00\x61\x00\x70\x00" nocase fullword
  condition:
    any of them
}
