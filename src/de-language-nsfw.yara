rule content_de_language_nsfw_2 {
  meta:
    info = "analritter"
  strings:
    $utf8 = "\x61\x6e\x61\x6c\x72\x69\x74\x74\x65\x72" nocase fullword
    $wide = "\x61\x00\x6e\x00\x61\x00\x6c\x00\x72\x00\x69\x00\x74\x00\x74\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_3 {
  meta:
    info = "arsch"
  strings:
    $utf8 = "\x61\x72\x73\x63\x68" nocase fullword
    $wide = "\x61\x00\x72\x00\x73\x00\x63\x00\x68\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_4 {
  meta:
    info = "arschficker"
  strings:
    $utf8 = "\x61\x72\x73\x63\x68\x66\x69\x63\x6b\x65\x72" nocase fullword
    $wide = "\x61\x00\x72\x00\x73\x00\x63\x00\x68\x00\x66\x00\x69\x00\x63\x00\x6b\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_5 {
  meta:
    info = "arschlecker"
  strings:
    $utf8 = "\x61\x72\x73\x63\x68\x6c\x65\x63\x6b\x65\x72" nocase fullword
    $wide = "\x61\x00\x72\x00\x73\x00\x63\x00\x68\x00\x6c\x00\x65\x00\x63\x00\x6b\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_6 {
  meta:
    info = "arschloch"
  strings:
    $utf8 = "\x61\x72\x73\x63\x68\x6c\x6f\x63\x68" nocase fullword
    $wide = "\x61\x00\x72\x00\x73\x00\x63\x00\x68\x00\x6c\x00\x6f\x00\x63\x00\x68\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_8 {
  meta:
    info = "bratze"
  strings:
    $utf8 = "\x62\x72\x61\x74\x7a\x65" nocase fullword
    $wide = "\x62\x00\x72\x00\x61\x00\x74\x00\x7a\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_9 {
  meta:
    info = "bumsen"
  strings:
    $utf8 = "\x62\x75\x6d\x73\x65\x6e" nocase fullword
    $wide = "\x62\x00\x75\x00\x6d\x00\x73\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_10 {
  meta:
    info = "dödel"
  strings:
    $utf8 = "\x64\xc3\xb6\x64\x65\x6c" nocase fullword
    $latin1 = "\x64\xf6\x64\x65\x6c" nocase fullword
    $cp1252 = "\x64\xf6\x64\x65\x6c" nocase fullword
    $wide = "\x64\x00\xf6\x00\x64\x00\x65\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_12 {
  meta:
    info = "ficken"
  strings:
    $utf8 = "\x66\x69\x63\x6b\x65\x6e" nocase fullword
    $wide = "\x66\x00\x69\x00\x63\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_13 {
  meta:
    info = "flittchen"
  strings:
    $utf8 = "\x66\x6c\x69\x74\x74\x63\x68\x65\x6e" nocase fullword
    $wide = "\x66\x00\x6c\x00\x69\x00\x74\x00\x74\x00\x63\x00\x68\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_14 {
  meta:
    info = "fotze"
  strings:
    $utf8 = "\x66\x6f\x74\x7a\x65" nocase fullword
    $wide = "\x66\x00\x6f\x00\x74\x00\x7a\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_15 {
  meta:
    info = "hackfresse"
  strings:
    $utf8 = "\x68\x61\x63\x6b\x66\x72\x65\x73\x73\x65" nocase fullword
    $wide = "\x68\x00\x61\x00\x63\x00\x6b\x00\x66\x00\x72\x00\x65\x00\x73\x00\x73\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_16 {
  meta:
    info = "hure"
  strings:
    $utf8 = "\x68\x75\x72\x65" nocase fullword
    $wide = "\x68\x00\x75\x00\x72\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_17 {
  meta:
    info = "hurensohn"
  strings:
    $utf8 = "\x68\x75\x72\x65\x6e\x73\x6f\x68\x6e" nocase fullword
    $wide = "\x68\x00\x75\x00\x72\x00\x65\x00\x6e\x00\x73\x00\x6f\x00\x68\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_18 {
  meta:
    info = "ische"
  strings:
    $utf8 = "\x69\x73\x63\x68\x65" nocase fullword
    $wide = "\x69\x00\x73\x00\x63\x00\x68\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_19 {
  meta:
    info = "kackbratze"
  strings:
    $utf8 = "\x6b\x61\x63\x6b\x62\x72\x61\x74\x7a\x65" nocase fullword
    $wide = "\x6b\x00\x61\x00\x63\x00\x6b\x00\x62\x00\x72\x00\x61\x00\x74\x00\x7a\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_22 {
  meta:
    info = "kackwurst"
  strings:
    $utf8 = "\x6b\x61\x63\x6b\x77\x75\x72\x73\x74" nocase fullword
    $wide = "\x6b\x00\x61\x00\x63\x00\x6b\x00\x77\x00\x75\x00\x72\x00\x73\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_23 {
  meta:
    info = "kampflesbe"
  strings:
    $utf8 = "\x6b\x61\x6d\x70\x66\x6c\x65\x73\x62\x65" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6d\x00\x70\x00\x66\x00\x6c\x00\x65\x00\x73\x00\x62\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_24 {
  meta:
    info = "kanake"
  strings:
    $utf8 = "\x6b\x61\x6e\x61\x6b\x65" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6e\x00\x61\x00\x6b\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_25 {
  meta:
    info = "morgenlatte"
  strings:
    $utf8 = "\x6d\x6f\x72\x67\x65\x6e\x6c\x61\x74\x74\x65" nocase fullword
    $wide = "\x6d\x00\x6f\x00\x72\x00\x67\x00\x65\x00\x6e\x00\x6c\x00\x61\x00\x74\x00\x74\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_26 {
  meta:
    info = "muschi"
  strings:
    $utf8 = "\x6d\x75\x73\x63\x68\x69" nocase fullword
    $wide = "\x6d\x00\x75\x00\x73\x00\x63\x00\x68\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_27 {
  meta:
    info = "möpse"
  strings:
    $utf8 = "\x6d\xc3\xb6\x70\x73\x65" nocase fullword
    $latin1 = "\x6d\xf6\x70\x73\x65" nocase fullword
    $cp1252 = "\x6d\xf6\x70\x73\x65" nocase fullword
    $wide = "\x6d\x00\xf6\x00\x70\x00\x73\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_28 {
  meta:
    info = "möse"
  strings:
    $utf8 = "\x6d\xc3\xb6\x73\x65" nocase fullword
    $latin1 = "\x6d\xf6\x73\x65" nocase fullword
    $cp1252 = "\x6d\xf6\x73\x65" nocase fullword
    $wide = "\x6d\x00\xf6\x00\x73\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_29 {
  meta:
    info = "neger"
  strings:
    $utf8 = "\x6e\x65\x67\x65\x72" nocase fullword
    $wide = "\x6e\x00\x65\x00\x67\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_30 {
  meta:
    info = "nigger"
  strings:
    $utf8 = "\x6e\x69\x67\x67\x65\x72" nocase fullword
    $wide = "\x6e\x00\x69\x00\x67\x00\x67\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_32 {
  meta:
    info = "nutte"
  strings:
    $utf8 = "\x6e\x75\x74\x74\x65" nocase fullword
    $wide = "\x6e\x00\x75\x00\x74\x00\x74\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_33 {
  meta:
    info = "onanieren"
  strings:
    $utf8 = "\x6f\x6e\x61\x6e\x69\x65\x72\x65\x6e" nocase fullword
    $wide = "\x6f\x00\x6e\x00\x61\x00\x6e\x00\x69\x00\x65\x00\x72\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_35 {
  meta:
    info = "pimmel"
  strings:
    $utf8 = "\x70\x69\x6d\x6d\x65\x6c" nocase fullword
    $wide = "\x70\x00\x69\x00\x6d\x00\x6d\x00\x65\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_36 {
  meta:
    info = "pimpern"
  strings:
    $utf8 = "\x70\x69\x6d\x70\x65\x72\x6e" nocase fullword
    $wide = "\x70\x00\x69\x00\x6d\x00\x70\x00\x65\x00\x72\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_38 {
  meta:
    info = "pissen"
  strings:
    $utf8 = "\x70\x69\x73\x73\x65\x6e" nocase fullword
    $wide = "\x70\x00\x69\x00\x73\x00\x73\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_39 {
  meta:
    info = "pisser"
  strings:
    $utf8 = "\x70\x69\x73\x73\x65\x72" nocase fullword
    $wide = "\x70\x00\x69\x00\x73\x00\x73\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_40 {
  meta:
    info = "poppen"
  strings:
    $utf8 = "\x70\x6f\x70\x70\x65\x6e" nocase fullword
    $wide = "\x70\x00\x6f\x00\x70\x00\x70\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_42 {
  meta:
    info = "reudig"
  strings:
    $utf8 = "\x72\x65\x75\x64\x69\x67" nocase fullword
    $wide = "\x72\x00\x65\x00\x75\x00\x64\x00\x69\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_43 {
  meta:
    info = "scheisser"
  strings:
    $utf8 = "\x73\x63\x68\x65\x69\x73\x73\x65\x72" nocase fullword
    $wide = "\x73\x00\x63\x00\x68\x00\x65\x00\x69\x00\x73\x00\x73\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_44 {
  meta:
    info = "scheiße"
  strings:
    $utf8 = "\x73\x63\x68\x65\x69\xc3\x9f\x65" nocase fullword
    $latin1 = "\x73\x63\x68\x65\x69\xdf\x65" nocase fullword
    $cp1252 = "\x73\x63\x68\x65\x69\xdf\x65" nocase fullword
    $wide = "\x73\x00\x63\x00\x68\x00\x65\x00\x69\x00\xdf\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_45 {
  meta:
    info = "schlampe"
  strings:
    $utf8 = "\x73\x63\x68\x6c\x61\x6d\x70\x65" nocase fullword
    $wide = "\x73\x00\x63\x00\x68\x00\x6c\x00\x61\x00\x6d\x00\x70\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_46 {
  meta:
    info = "schnackeln"
  strings:
    $utf8 = "\x73\x63\x68\x6e\x61\x63\x6b\x65\x6c\x6e" nocase fullword
    $wide = "\x73\x00\x63\x00\x68\x00\x6e\x00\x61\x00\x63\x00\x6b\x00\x65\x00\x6c\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_47 {
  meta:
    info = "schwanzlutscher"
  strings:
    $utf8 = "\x73\x63\x68\x77\x61\x6e\x7a\x6c\x75\x74\x73\x63\x68\x65\x72" nocase fullword
    $wide = "\x73\x00\x63\x00\x68\x00\x77\x00\x61\x00\x6e\x00\x7a\x00\x6c\x00\x75\x00\x74\x00\x73\x00\x63\x00\x68\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_48 {
  meta:
    info = "schwuchtel"
  strings:
    $utf8 = "\x73\x63\x68\x77\x75\x63\x68\x74\x65\x6c" nocase fullword
    $wide = "\x73\x00\x63\x00\x68\x00\x77\x00\x75\x00\x63\x00\x68\x00\x74\x00\x65\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_49 {
  meta:
    info = "tittchen"
  strings:
    $utf8 = "\x74\x69\x74\x74\x63\x68\x65\x6e" nocase fullword
    $wide = "\x74\x00\x69\x00\x74\x00\x74\x00\x63\x00\x68\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_50 {
  meta:
    info = "titten"
  strings:
    $utf8 = "\x74\x69\x74\x74\x65\x6e" nocase fullword
    $wide = "\x74\x00\x69\x00\x74\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_51 {
  meta:
    info = "vollpfosten"
  strings:
    $utf8 = "\x76\x6f\x6c\x6c\x70\x66\x6f\x73\x74\x65\x6e" nocase fullword
    $wide = "\x76\x00\x6f\x00\x6c\x00\x6c\x00\x70\x00\x66\x00\x6f\x00\x73\x00\x74\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_52 {
  meta:
    info = "vögeln"
  strings:
    $utf8 = "\x76\xc3\xb6\x67\x65\x6c\x6e" nocase fullword
    $latin1 = "\x76\xf6\x67\x65\x6c\x6e" nocase fullword
    $cp1252 = "\x76\xf6\x67\x65\x6c\x6e" nocase fullword
    $wide = "\x76\x00\xf6\x00\x67\x00\x65\x00\x6c\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_de_language_nsfw_53 {
  meta:
    info = "wichse"
  strings:
    $utf8 = "\x77\x69\x63\x68\x73\x65" nocase fullword
    $wide = "\x77\x00\x69\x00\x63\x00\x68\x00\x73\x00\x65\x00" nocase fullword
  condition:
    any of them
}
