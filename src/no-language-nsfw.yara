rule content_no_language_nsfw_1 {
  meta:
    info = "drittsekk"
  strings:
    $utf8 = "\x64\x72\x69\x74\x74\x73\x65\x6b\x6b" nocase fullword
    $wide = "\x64\x00\x72\x00\x69\x00\x74\x00\x74\x00\x73\x00\x65\x00\x6b\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_2 {
  meta:
    info = "faen i helvete"
  strings:
    $utf8 = "\x66\x61\x65\x6e\x20\x69\x20\x68\x65\x6c\x76\x65\x74\x65" nocase fullword
    $wide = "\x66\x00\x61\x00\x65\x00\x6e\x00\x20\x00\x69\x00\x20\x00\x68\x00\x65\x00\x6c\x00\x76\x00\x65\x00\x74\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_3 {
  meta:
    info = "fitte"
  strings:
    $utf8 = "\x66\x69\x74\x74\x65" nocase fullword
    $wide = "\x66\x00\x69\x00\x74\x00\x74\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_4 {
  meta:
    info = "jævla"
  strings:
    $utf8 = "\x6a\xc3\xa6\x76\x6c\x61" nocase fullword
    $wide = "\x6a\x00\xe6\x00\x76\x00\x6c\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_6 {
  meta:
    info = "kukene"
  strings:
    $utf8 = "\x6b\x75\x6b\x65\x6e\x65" nocase fullword
    $wide = "\x6b\x00\x75\x00\x6b\x00\x65\x00\x6e\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_7 {
  meta:
    info = "kuker"
  strings:
    $utf8 = "\x6b\x75\x6b\x65\x72" nocase fullword
    $wide = "\x6b\x00\x75\x00\x6b\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_9 {
  meta:
    info = "pikk"
  strings:
    $utf8 = "\x70\x69\x6b\x6b" nocase fullword
    $wide = "\x70\x00\x69\x00\x6b\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_10 {
  meta:
    info = "sotrør"
  strings:
    $utf8 = "\x73\x6f\x74\x72\xc3\xb8\x72" nocase fullword
    $wide = "\x73\x00\x6f\x00\x74\x00\x72\x00\xf8\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_11 {
  meta:
    info = "ståpikk"
  strings:
    $utf8 = "\x73\x74\xc3\xa5\x70\x69\x6b\x6b" nocase fullword
    $wide = "\x73\x00\x74\x00\xe5\x00\x70\x00\x69\x00\x6b\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_12 {
  meta:
    info = "ståpikkene"
  strings:
    $utf8 = "\x73\x74\xc3\xa5\x70\x69\x6b\x6b\x65\x6e\x65" nocase fullword
    $wide = "\x73\x00\x74\x00\xe5\x00\x70\x00\x69\x00\x6b\x00\x6b\x00\x65\x00\x6e\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_13 {
  meta:
    info = "ståpikker"
  strings:
    $utf8 = "\x73\x74\xc3\xa5\x70\x69\x6b\x6b\x65\x72" nocase fullword
    $wide = "\x73\x00\x74\x00\xe5\x00\x70\x00\x69\x00\x6b\x00\x6b\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}
