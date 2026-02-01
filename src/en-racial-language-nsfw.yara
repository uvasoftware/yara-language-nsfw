rule content_en_racial_language_nsfw_racial_1 {
  meta:
    info = "kike"
  strings:
    $utf8 = "\x6b\x69\x6b\x65" nocase fullword
    $wide = "\x6b\x00\x69\x00\x6b\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_en_racial_language_nsfw_racial_2 {
  meta:
    info = "beaner"
  strings:
    $utf8 = "\x62\x65\x61\x6e\x65\x72" nocase fullword
    $wide = "\x62\x00\x65\x00\x61\x00\x6e\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_en_racial_language_nsfw_racial_3 {
  meta:
    info = "nig nog"
  strings:
    $utf8 = "\x6e\x69\x67\x20\x6e\x6f\x67" nocase fullword
    $wide = "\x6e\x00\x69\x00\x67\x00\x20\x00\x6e\x00\x6f\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_en_racial_language_nsfw_racial_4 {
  meta:
    info = "nigga"
  strings:
    $utf8 = "\x6e\x69\x67\x67\x61" nocase fullword
    $wide = "\x6e\x00\x69\x00\x67\x00\x67\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_en_racial_language_nsfw_racial_5 {
  meta:
    info = "nigger"
  strings:
    $utf8 = "\x6e\x69\x67\x67\x65\x72" nocase fullword
    $wide = "\x6e\x00\x69\x00\x67\x00\x67\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_en_racial_language_nsfw_racial_6 {
  meta:
    info = "raghead"
  strings:
    $utf8 = "\x72\x61\x67\x68\x65\x61\x64" nocase fullword
    $wide = "\x72\x00\x61\x00\x67\x00\x68\x00\x65\x00\x61\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_en_racial_language_nsfw_racial_7 {
  meta:
    info = "slanteye"
  strings:
    $utf8 = "\x73\x6c\x61\x6e\x74\x65\x79\x65" nocase fullword
    $wide = "\x73\x00\x6c\x00\x61\x00\x6e\x00\x74\x00\x65\x00\x79\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_en_racial_language_nsfw_racial_8 {
  meta:
    info = "towelhead"
  strings:
    $utf8 = "\x74\x6f\x77\x65\x6c\x68\x65\x61\x64" nocase fullword
    $wide = "\x74\x00\x6f\x00\x77\x00\x65\x00\x6c\x00\x68\x00\x65\x00\x61\x00\x64\x00" nocase fullword
  condition:
    any of them
}
rule content_en_racial_language_nsfw_racial_9 {
  meta:
    info = "whity"
  strings:
    $utf8 = "\x77\x68\x69\x74\x79" nocase fullword
    $wide = "\x77\x00\x68\x00\x69\x00\x74\x00\x79\x00" nocase fullword
  condition:
    any of them
}
rule content_en_racial_language_nsfw_racial_10 {
  meta:
    info = "wetback"
  strings:
    $utf8 = "\x77\x65\x74\x62\x61\x63\x6b" nocase fullword
    $wide = "\x77\x00\x65\x00\x74\x00\x62\x00\x61\x00\x63\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_en_racial_language_nsfw_racial_11 {
  meta:
    info = "spic"
  strings:
    $utf8 = "\x73\x70\x69\x63" nocase fullword
    $wide = "\x73\x00\x70\x00\x69\x00\x63\x00" nocase fullword
  condition:
    any of them
}
