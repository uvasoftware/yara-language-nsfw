
rule content_pt_language_nsfw_2 {
  meta:
    info = "balalao"
  strings:
    $utf8 = "\x62\x61\x6c\x61\x6c\x61\x6f" nocase fullword
    $latin1 = "\x62\x61\x6c\x61\x6c\x61\x6f" nocase fullword
    $cp1252 = "\x62\x61\x6c\x61\x6c\x61\x6f" nocase fullword
    $wide = "\x62\x00\x61\x00\x6c\x00\x61\x00\x6c\x00\x61\x00\x6f\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_7 {
  meta:
    info = "braulio de borracha"
  strings:
    $utf8 = "\x62\x72\x61\x75\x6c\x69\x6f\x20\x64\x65\x20\x62\x6f\x72\x72\x61\x63\x68\x61" nocase fullword
    $latin1 = "\x62\x72\x61\x75\x6c\x69\x6f\x20\x64\x65\x20\x62\x6f\x72\x72\x61\x63\x68\x61" nocase fullword
    $cp1252 = "\x62\x72\x61\x75\x6c\x69\x6f\x20\x64\x65\x20\x62\x6f\x72\x72\x61\x63\x68\x61" nocase fullword
    $wide = "\x62\x00\x72\x00\x61\x00\x75\x00\x6c\x00\x69\x00\x6f\x00\x20\x00\x64\x00\x65\x00\x20\x00\x62\x00\x6f\x00\x72\x00\x72\x00\x61\x00\x63\x00\x68\x00\x61\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_18 {
  meta:
    info = "foda-se"
  strings:
    $utf8 = "\x66\x6f\x64\x61\x2d\x73\x65" nocase fullword
    $latin1 = "\x66\x6f\x64\x61\x2d\x73\x65" nocase fullword
    $cp1252 = "\x66\x6f\x64\x61\x2d\x73\x65" nocase fullword
    $wide = "\x66\x00\x6f\x00\x64\x00\x61\x00\x2d\x00\x73\x00\x65\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_19 {
  meta:
    info = "foder"
  strings:
    $utf8 = "\x66\x6f\x64\x65\x72" nocase fullword
    $latin1 = "\x66\x6f\x64\x65\x72" nocase fullword
    $cp1252 = "\x66\x6f\x64\x65\x72" nocase fullword
    $wide = "\x66\x00\x6f\x00\x64\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}


rule content_pt_language_nsfw_25 {
  meta:
    info = "putinha"
  strings:
    $utf8 = "\x70\x75\x74\x69\x6e\x68\x61" nocase fullword
    $latin1 = "\x70\x75\x74\x69\x6e\x68\x61" nocase fullword
    $cp1252 = "\x70\x75\x74\x69\x6e\x68\x61" nocase fullword
    $wide = "\x70\x00\x75\x00\x74\x00\x69\x00\x6e\x00\x68\x00\x61\x00" nocase fullword
  condition:
    any of them
}



rule content_pt_language_nsfw_33 {
  meta:
    info = "viadão"
  strings:
    $utf8 = "\x76\x69\x61\x64\xc3\xa3\x6f" nocase fullword
    $latin1 = "\x76\x69\x61\x64\xe3\x6f" nocase fullword
    $cp1252 = "\x76\x69\x61\x64\xe3\x6f" nocase fullword
    $wide = "\x76\x00\x69\x00\x61\x00\x64\x00\xe3\x00\x6f\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_34 {
  meta:
    info = "caralho"
  strings:
    $utf8 = "\x63\x61\x72\x61\x6c\x68\x6f" nocase fullword
    $latin1 = "\x63\x61\x72\x61\x6c\x68\x6f" nocase fullword
    $cp1252 = "\x63\x61\x72\x61\x6c\x68\x6f" nocase fullword
    $wide = "\x63\x00\x61\x00\x72\x00\x61\x00\x6c\x00\x68\x00\x6f\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_37 {
  meta:
    info = "Punhetão"
  strings:
    $utf8 = "\x50\x75\x6e\x68\x65\x74\xc3\xa3\x6f" nocase fullword
    $latin1 = "\x50\x75\x6e\x68\x65\x74\xe3\x6f" nocase fullword
    $cp1252 = "\x50\x75\x6e\x68\x65\x74\xe3\x6f" nocase fullword
    $wide = "\x50\x00\x75\x00\x6e\x00\x68\x00\x65\x00\x74\x00\xe3\x00\x6f\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_38 {
  meta:
    info = "Xochota"
  strings:
    $utf8 = "\x58\x6f\x63\x68\x6f\x74\x61" nocase fullword
    $latin1 = "\x58\x6f\x63\x68\x6f\x74\x61" nocase fullword
    $cp1252 = "\x58\x6f\x63\x68\x6f\x74\x61" nocase fullword
    $wide = "\x58\x00\x6f\x00\x63\x00\x68\x00\x6f\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_40 {
  meta:
    info = "Xoxota"
  strings:
    $utf8 = "\x58\x6f\x78\x6f\x74\x61" nocase fullword
    $latin1 = "\x58\x6f\x78\x6f\x74\x61" nocase fullword
    $cp1252 = "\x58\x6f\x78\x6f\x74\x61" nocase fullword
    $wide = "\x58\x00\x6f\x00\x78\x00\x6f\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_41 {
  meta:
    info = "Buceta"
  strings:
    $utf8 = "\x42\x75\x63\x65\x74\x61" nocase fullword
    $latin1 = "\x42\x75\x63\x65\x74\x61" nocase fullword
    $cp1252 = "\x42\x75\x63\x65\x74\x61" nocase fullword
    $wide = "\x42\x00\x75\x00\x63\x00\x65\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_42 {
  meta:
    info = "Busseta"
  strings:
    $utf8 = "\x42\x75\x73\x73\x65\x74\x61" nocase fullword
    $latin1 = "\x42\x75\x73\x73\x65\x74\x61" nocase fullword
    $cp1252 = "\x42\x75\x73\x73\x65\x74\x61" nocase fullword
    $wide = "\x42\x00\x75\x00\x73\x00\x73\x00\x65\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_44 {
  meta:
    info = "Boiola"
  strings:
    $utf8 = "\x42\x6f\x69\x6f\x6c\x61" nocase fullword
    $latin1 = "\x42\x6f\x69\x6f\x6c\x61" nocase fullword
    $cp1252 = "\x42\x6f\x69\x6f\x6c\x61" nocase fullword
    $wide = "\x42\x00\x6f\x00\x69\x00\x6f\x00\x6c\x00\x61\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_45 {
  meta:
    info = "Chereca"
  strings:
    $utf8 = "\x43\x68\x65\x72\x65\x63\x61" nocase fullword
    $latin1 = "\x43\x68\x65\x72\x65\x63\x61" nocase fullword
    $cp1252 = "\x43\x68\x65\x72\x65\x63\x61" nocase fullword
    $wide = "\x43\x00\x68\x00\x65\x00\x72\x00\x65\x00\x63\x00\x61\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_48 {
  meta:
    info = "cuzao"
  strings:
    $utf8_1 = "\x63\x75\x7a\x61\x6f" nocase fullword
    $latin1_1 = "\x63\x75\x7a\x61\x6f" nocase fullword
    $cp1252_1 = "\x63\x75\x7a\x61\x6f" nocase fullword
    $wide_1 = "\x63\x00\x75\x00\x7a\x00\x61\x00\x6f\x00" nocase fullword
    $utf8_2 = "\x63\x75\x7a\xc3\xa3\x6f" nocase fullword
    $latin1_2 = "\x63\x75\x7a\xe3\x6f" nocase fullword
    $cp1252_2 = "\x63\x75\x7a\xe3\x6f" nocase fullword
    $wide_2 = "\x63\x00\x75\x00\x7a\x00\xe3\x00\x6f\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_49 {
  meta:
    info = "arrombado"
  strings:
    $utf8_1 = "\x61\x72\x72\x6f\x6d\x62\x61\x64\x6f" nocase fullword
    $latin1_1 = "\x61\x72\x72\x6f\x6d\x62\x61\x64\x6f" nocase fullword
    $cp1252_1 = "\x61\x72\x72\x6f\x6d\x62\x61\x64\x6f" nocase fullword
    $wide_1 = "\x61\x00\x72\x00\x72\x00\x6f\x00\x6d\x00\x62\x00\x61\x00\x64\x00\x6f\x00" nocase fullword
    $utf8_2 = "\x61\x72\x72\x6f\x6d\x62\x61\x64\x61" nocase fullword
    $latin1_2 = "\x61\x72\x72\x6f\x6d\x62\x61\x64\x61" nocase fullword
    $cp1252_2 = "\x61\x72\x72\x6f\x6d\x62\x61\x64\x61" nocase fullword
    $wide_2 = "\x61\x00\x72\x00\x72\x00\x6f\x00\x6d\x00\x62\x00\x61\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_51 {
  meta:
    info = "vai se foder"
  strings:
    $utf8 = "\x76\x61\x69\x20\x73\x65\x20\x66\x6f\x64\x65\x72" nocase fullword
    $latin1 = "\x76\x61\x69\x20\x73\x65\x20\x66\x6f\x64\x65\x72" nocase fullword
    $cp1252 = "\x76\x61\x69\x20\x73\x65\x20\x66\x6f\x64\x65\x72" nocase fullword
    $wide = "\x76\x00\x61\x00\x69\x00\x20\x00\x73\x00\x65\x00\x20\x00\x66\x00\x6f\x00\x64\x00\x65\x00\x72\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_55 {
  meta:
    info = "broxa"
  strings:
    $utf8 = "\x62\x72\x6f\x78\x61" nocase fullword
    $latin1 = "\x62\x72\x6f\x78\x61" nocase fullword
    $cp1252 = "\x62\x72\x6f\x78\x61" nocase fullword
    $wide = "\x62\x00\x72\x00\x6f\x00\x78\x00\x61\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_58 {
  meta:
    info = "pirocudo"
  strings:
    $utf8 = "\x70\x69\x72\x6f\x63\x75\x64\x6f" nocase fullword
    $latin1 = "\x70\x69\x72\x6f\x63\x75\x64\x6f" nocase fullword
    $cp1252 = "\x70\x69\x72\x6f\x63\x75\x64\x6f" nocase fullword
    $wide = "\x70\x00\x69\x00\x72\x00\x6f\x00\x63\x00\x75\x00\x64\x00\x6f\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_puta {
  meta:
    info = "puta"
  strings:
    $utf8 = "\x70\x75\x74\x61" nocase fullword
    $latin1 = "\x70\x75\x74\x61" nocase fullword
    $cp1252 = "\x70\x75\x74\x61" nocase fullword
    $wide = "\x70\x00\x75\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}

rule content_pt_language_nsfw_test {
  meta:
    info = "Test rule for pt language detection - UUID: 4F5A6B7C-8D9E-40F1-A2B3-C4D5E6F7A8B9"
  strings:
    $ = "4F5A6B7C-8D9E-40F1-A2B3-C4D5E6F7A8B9" fullword wide ascii nocase
  condition:
    any of them
}
