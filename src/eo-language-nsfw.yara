rule content_eo_language_nsfw_1 {
  meta:
    info = "bugren"
  strings:
    $utf8 = "\x62\x75\x67\x72\x65\x6e" nocase fullword
    $wide = "\x62\x00\x75\x00\x67\x00\x72\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_2 {
  meta:
    info = "bugri"
  strings:
    $utf8 = "\x62\x75\x67\x72\x69" nocase fullword
    $wide = "\x62\x00\x75\x00\x67\x00\x72\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_3 {
  meta:
    info = "bugru"
  strings:
    $utf8 = "\x62\x75\x67\x72\x75" nocase fullword
    $wide = "\x62\x00\x75\x00\x67\x00\x72\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_4 {
  meta:
    info = "diofek"
  strings:
    $utf8 = "\x64\x69\x6f\x66\x65\x6b" nocase fullword
    $wide = "\x64\x00\x69\x00\x6f\x00\x66\x00\x65\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_5 {
  meta:
    info = "diofeka"
  strings:
    $utf8 = "\x64\x69\x6f\x66\x65\x6b\x61" nocase fullword
    $wide = "\x64\x00\x69\x00\x6f\x00\x66\x00\x65\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_6 {
  meta:
    info = "fek"
  strings:
    $utf8 = "\x66\x65\x6b" nocase fullword
    $wide = "\x66\x00\x65\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_7 {
  meta:
    info = "feken"
  strings:
    $utf8 = "\x66\x65\x6b\x65\x6e" nocase fullword
    $wide = "\x66\x00\x65\x00\x6b\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_8 {
  meta:
    info = "fekfikanto"
  strings:
    $utf8 = "\x66\x65\x6b\x66\x69\x6b\x61\x6e\x74\x6f" nocase fullword
    $wide = "\x66\x00\x65\x00\x6b\x00\x66\x00\x69\x00\x6b\x00\x61\x00\x6e\x00\x74\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_9 {
  meta:
    info = "feklekulo"
  strings:
    $utf8 = "\x66\x65\x6b\x6c\x65\x6b\x75\x6c\x6f" nocase fullword
    $wide = "\x66\x00\x65\x00\x6b\x00\x6c\x00\x65\x00\x6b\x00\x75\x00\x6c\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_10 {
  meta:
    info = "fekulo"
  strings:
    $utf8 = "\x66\x65\x6b\x75\x6c\x6f" nocase fullword
    $wide = "\x66\x00\x65\x00\x6b\x00\x75\x00\x6c\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_11 {
  meta:
    info = "fik"
  strings:
    $utf8 = "\x66\x69\x6b" nocase fullword
    $wide = "\x66\x00\x69\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_12 {
  meta:
    info = "fikado"
  strings:
    $utf8 = "\x66\x69\x6b\x61\x64\x6f" nocase fullword
    $wide = "\x66\x00\x69\x00\x6b\x00\x61\x00\x64\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_13 {
  meta:
    info = "fikema"
  strings:
    $utf8 = "\x66\x69\x6b\x65\x6d\x61" nocase fullword
    $wide = "\x66\x00\x69\x00\x6b\x00\x65\x00\x6d\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_14 {
  meta:
    info = "fikfek"
  strings:
    $utf8 = "\x66\x69\x6b\x66\x65\x6b" nocase fullword
    $wide = "\x66\x00\x69\x00\x6b\x00\x66\x00\x65\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_15 {
  meta:
    info = "fiki"
  strings:
    $utf8 = "\x66\x69\x6b\x69" nocase fullword
    $wide = "\x66\x00\x69\x00\x6b\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_16 {
  meta:
    info = "fikilo"
  strings:
    $utf8 = "\x66\x69\x6b\x69\x6c\x6f" nocase fullword
    $wide = "\x66\x00\x69\x00\x6b\x00\x69\x00\x6c\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_17 {
  meta:
    info = "fikiĝi"
  strings:
    $utf8 = "\x66\x69\x6b\x69\xc4\x9d\x69" nocase fullword
    $wide = "\x66\x00\x69\x00\x6b\x00\x69\x00\x1d\x01\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_18 {
  meta:
    info = "fikiĝu"
  strings:
    $utf8 = "\x66\x69\x6b\x69\xc4\x9d\x75" nocase fullword
    $wide = "\x66\x00\x69\x00\x6b\x00\x69\x00\x1d\x01\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_19 {
  meta:
    info = "fikklaŭno"
  strings:
    $utf8 = "\x66\x69\x6b\x6b\x6c\x61\xc5\xad\x6e\x6f" nocase fullword
    $wide = "\x66\x00\x69\x00\x6b\x00\x6b\x00\x6c\x00\x61\x00\x6d\x01\x6e\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_20 {
  meta:
    info = "fikota"
  strings:
    $utf8 = "\x66\x69\x6b\x6f\x74\x61" nocase fullword
    $wide = "\x66\x00\x69\x00\x6b\x00\x6f\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_21 {
  meta:
    info = "fiku"
  strings:
    $utf8 = "\x66\x69\x6b\x75" nocase fullword
    $wide = "\x66\x00\x69\x00\x6b\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_22 {
  meta:
    info = "forfiki"
  strings:
    $utf8 = "\x66\x6f\x72\x66\x69\x6b\x69" nocase fullword
    $wide = "\x66\x00\x6f\x00\x72\x00\x66\x00\x69\x00\x6b\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_23 {
  meta:
    info = "forfikiĝu"
  strings:
    $utf8 = "\x66\x6f\x72\x66\x69\x6b\x69\xc4\x9d\x75" nocase fullword
    $wide = "\x66\x00\x6f\x00\x72\x00\x66\x00\x69\x00\x6b\x00\x69\x00\x1d\x01\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_24 {
  meta:
    info = "forfiku"
  strings:
    $utf8 = "\x66\x6f\x72\x66\x69\x6b\x75" nocase fullword
    $wide = "\x66\x00\x6f\x00\x72\x00\x66\x00\x69\x00\x6b\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_25 {
  meta:
    info = "forfurzu"
  strings:
    $utf8 = "\x66\x6f\x72\x66\x75\x72\x7a\x75" nocase fullword
    $wide = "\x66\x00\x6f\x00\x72\x00\x66\x00\x75\x00\x72\x00\x7a\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_26 {
  meta:
    info = "forpisi"
  strings:
    $utf8 = "\x66\x6f\x72\x70\x69\x73\x69" nocase fullword
    $wide = "\x66\x00\x6f\x00\x72\x00\x70\x00\x69\x00\x73\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_27 {
  meta:
    info = "forpisu"
  strings:
    $utf8 = "\x66\x6f\x72\x70\x69\x73\x75" nocase fullword
    $wide = "\x66\x00\x6f\x00\x72\x00\x70\x00\x69\x00\x73\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_28 {
  meta:
    info = "furzulo"
  strings:
    $utf8 = "\x66\x75\x72\x7a\x75\x6c\x6f" nocase fullword
    $wide = "\x66\x00\x75\x00\x72\x00\x7a\x00\x75\x00\x6c\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_29 {
  meta:
    info = "kacen"
  strings:
    $utf8 = "\x6b\x61\x63\x65\x6e" nocase fullword
    $wide = "\x6b\x00\x61\x00\x63\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_30 {
  meta:
    info = "kaco"
  strings:
    $utf8 = "\x6b\x61\x63\x6f" nocase fullword
    $wide = "\x6b\x00\x61\x00\x63\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_31 {
  meta:
    info = "kacsuĉulo"
  strings:
    $utf8 = "\x6b\x61\x63\x73\x75\xc4\x89\x75\x6c\x6f" nocase fullword
    $wide = "\x6b\x00\x61\x00\x63\x00\x73\x00\x75\x00\x09\x01\x75\x00\x6c\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_32 {
  meta:
    info = "kojono"
  strings:
    $utf8 = "\x6b\x6f\x6a\x6f\x6e\x6f" nocase fullword
    $wide = "\x6b\x00\x6f\x00\x6a\x00\x6f\x00\x6e\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_33 {
  meta:
    info = "piĉen"
  strings:
    $utf8 = "\x70\x69\xc4\x89\x65\x6e" nocase fullword
    $wide = "\x70\x00\x69\x00\x09\x01\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_34 {
  meta:
    info = "piĉo"
  strings:
    $utf8 = "\x70\x69\xc4\x89\x6f" nocase fullword
    $wide = "\x70\x00\x69\x00\x09\x01\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_35 {
  meta:
    info = "zamenfek"
  strings:
    $utf8 = "\x7a\x61\x6d\x65\x6e\x66\x65\x6b" nocase fullword
    $wide = "\x7a\x00\x61\x00\x6d\x00\x65\x00\x6e\x00\x66\x00\x65\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_36 {
  meta:
    info = "ĉiesulino"
  strings:
    $utf8 = "\xc4\x89\x69\x65\x73\x75\x6c\x69\x6e\x6f" nocase fullword
    $wide = "\x09\x01\x69\x00\x65\x00\x73\x00\x75\x00\x6c\x00\x69\x00\x6e\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_eo_language_nsfw_37 {
  meta:
    info = "ĉiesulo"
  strings:
    $utf8 = "\xc4\x89\x69\x65\x73\x75\x6c\x6f" nocase fullword
    $wide = "\x09\x01\x69\x00\x65\x00\x73\x00\x75\x00\x6c\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
