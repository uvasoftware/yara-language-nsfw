rule content_da_language_nsfw_2 {
  meta:
    info = "bøsserøv"
  strings:
    $utf8 = "\x62\xc3\xb8\x73\x73\x65\x72\xc3\xb8\x76" nocase fullword
    $wide = "\x62\x00\xf8\x00\x73\x00\x73\x00\x65\x00\x72\x00\xf8\x00\x76\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_4 {
  meta:
    info = "fisse"
  strings:
    $utf8 = "\x66\x69\x73\x73\x65" nocase fullword
    $wide = "\x66\x00\x69\x00\x73\x00\x73\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_5 {
  meta:
    info = "fissehår"
  strings:
    $utf8 = "\x66\x69\x73\x73\x65\x68\xc3\xa5\x72" nocase fullword
    $wide = "\x66\x00\x69\x00\x73\x00\x73\x00\x65\x00\x68\x00\xe5\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_7 {
  meta:
    info = "hestepik"
  strings:
    $utf8 = "\x68\x65\x73\x74\x65\x70\x69\x6b" nocase fullword
    $wide = "\x68\x00\x65\x00\x73\x00\x74\x00\x65\x00\x70\x00\x69\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_8 {
  meta:
    info = "kussekryller"
  strings:
    $utf8 = "\x6b\x75\x73\x73\x65\x6b\x72\x79\x6c\x6c\x65\x72" nocase fullword
    $wide = "\x6b\x00\x75\x00\x73\x00\x73\x00\x65\x00\x6b\x00\x72\x00\x79\x00\x6c\x00\x6c\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_10 {
  meta:
    info = "luder"
  strings:
    $utf8 = "\x6c\x75\x64\x65\x72" nocase fullword
    $wide = "\x6c\x00\x75\x00\x64\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_11 {
  meta:
    info = "pik"
  strings:
    $utf8 = "\x70\x69\x6b" nocase fullword
    $wide = "\x70\x00\x69\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_12 {
  meta:
    info = "pikhår"
  strings:
    $utf8 = "\x70\x69\x6b\x68\xc3\xa5\x72" nocase fullword
    $wide = "\x70\x00\x69\x00\x6b\x00\x68\x00\xe5\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_13 {
  meta:
    info = "pikslugeri"
  strings:
    $utf8 = "\x70\x69\x6b\x73\x6c\x75\x67\x65\x72\x69" nocase fullword
    $wide = "\x70\x00\x69\x00\x6b\x00\x73\x00\x6c\x00\x75\x00\x67\x00\x65\x00\x72\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_14 {
  meta:
    info = "piksutteri"
  strings:
    $utf8 = "\x70\x69\x6b\x73\x75\x74\x74\x65\x72\x69" nocase fullword
    $wide = "\x70\x00\x69\x00\x6b\x00\x73\x00\x75\x00\x74\x00\x74\x00\x65\x00\x72\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_16 {
  meta:
    info = "røv"
  strings:
    $utf8 = "\x72\xc3\xb8\x76" nocase fullword
    $wide = "\x72\x00\xf8\x00\x76\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_17 {
  meta:
    info = "røvhul"
  strings:
    $utf8 = "\x72\xc3\xb8\x76\x68\x75\x6c" nocase fullword
    $wide = "\x72\x00\xf8\x00\x76\x00\x68\x00\x75\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_18 {
  meta:
    info = "røvskæg"
  strings:
    $utf8 = "\x72\xc3\xb8\x76\x73\x6b\xc3\xa6\x67" nocase fullword
    $wide = "\x72\x00\xf8\x00\x76\x00\x73\x00\x6b\x00\xe6\x00\x67\x00" nocase fullword
  condition:
    any of them
}
rule content_da_language_nsfw_19 {
  meta:
    info = "røvspræke"
  strings:
    $utf8 = "\x72\xc3\xb8\x76\x73\x70\x72\xc3\xa6\x6b\x65" nocase fullword
    $wide = "\x72\x00\xf8\x00\x76\x00\x73\x00\x70\x00\x72\x00\xe6\x00\x6b\x00\x65\x00" nocase fullword
  condition:
    any of them
}
