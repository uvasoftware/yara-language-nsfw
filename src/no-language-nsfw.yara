rule content_no_language_nsfw_3 {
  meta:
    info = "fitte"
  strings:
    $utf8 = "\x66\x69\x74\x74\x65" nocase fullword
    $wide = "\x66\x00\x69\x00\x74\x00\x74\x00\x65\x00" nocase fullword
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
    $latin1 = "\x73\x6f\x74\x72\xf8\x72" nocase fullword
    $cp1252 = "\x73\x6f\x74\x72\xf8\x72" nocase fullword
    $wide = "\x73\x00\x6f\x00\x74\x00\x72\x00\xf8\x00\x72\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_11 {
  meta:
    info = "ståpikk"
  strings:
    $utf8 = "\x73\x74\xc3\xa5\x70\x69\x6b\x6b" nocase fullword
    $latin1 = "\x73\x74\xe5\x70\x69\x6b\x6b" nocase fullword
    $cp1252 = "\x73\x74\xe5\x70\x69\x6b\x6b" nocase fullword
    $wide = "\x73\x00\x74\x00\xe5\x00\x70\x00\x69\x00\x6b\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_12 {
  meta:
    info = "ståpikkene"
  strings:
    $utf8 = "\x73\x74\xc3\xa5\x70\x69\x6b\x6b\x65\x6e\x65" nocase fullword
    $latin1 = "\x73\x74\xe5\x70\x69\x6b\x6b\x65\x6e\x65" nocase fullword
    $cp1252 = "\x73\x74\xe5\x70\x69\x6b\x6b\x65\x6e\x65" nocase fullword
    $wide = "\x73\x00\x74\x00\xe5\x00\x70\x00\x69\x00\x6b\x00\x6b\x00\x65\x00\x6e\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_no_language_nsfw_13 {
  meta:
    info = "ståpikker"
  strings:
    $utf8 = "\x73\x74\xc3\xa5\x70\x69\x6b\x6b\x65\x72" nocase fullword
    $latin1 = "\x73\x74\xe5\x70\x69\x6b\x6b\x65\x72" nocase fullword
    $cp1252 = "\x73\x74\xe5\x70\x69\x6b\x6b\x65\x72" nocase fullword
    $wide = "\x73\x00\x74\x00\xe5\x00\x70\x00\x69\x00\x6b\x00\x6b\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}

rule content_no_language_nsfw_test {
  meta:
    info = "Test rule for no language detection - UUID: 2E3F4A5B-6C7D-48E9-F0A1-B2C3D4E5F6A7"
  strings:
    $ = "2E3F4A5B-6C7D-48E9-F0A1-B2C3D4E5F6A7" fullword wide ascii nocase
  condition:
    any of them
}
