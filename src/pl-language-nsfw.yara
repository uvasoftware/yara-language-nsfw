rule content_pl_language_nsfw_1 {
  meta:
    info = "burdel"
  strings:
    $utf8 = "\x62\x75\x72\x64\x65\x6c" nocase fullword
    $wide = "\x62\x00\x75\x00\x72\x00\x64\x00\x65\x00\x6c\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_2 {
  meta:
    info = "burdelmama"
  strings:
    $utf8 = "\x62\x75\x72\x64\x65\x6c\x6d\x61\x6d\x61" nocase fullword
    $wide = "\x62\x00\x75\x00\x72\x00\x64\x00\x65\x00\x6c\x00\x6d\x00\x61\x00\x6d\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_3 {
  meta:
    info = "chuj"
  strings:
    $utf8 = "\x63\x68\x75\x6a" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x6a\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_4 {
  meta:
    info = "chujnia"
  strings:
    $utf8 = "\x63\x68\x75\x6a\x6e\x69\x61" nocase fullword
    $wide = "\x63\x00\x68\x00\x75\x00\x6a\x00\x6e\x00\x69\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_5 {
  meta:
    info = "ciota"
  strings:
    $utf8 = "\x63\x69\x6f\x74\x61" nocase fullword
    $wide = "\x63\x00\x69\x00\x6f\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_6 {
  meta:
    info = "cipa"
  strings:
    $utf8 = "\x63\x69\x70\x61" nocase fullword
    $wide = "\x63\x00\x69\x00\x70\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_9 {
  meta:
    info = "dmuchać"
  strings:
    $utf8 = "\x64\x6d\x75\x63\x68\x61\xc4\x87" nocase fullword
    $wide = "\x64\x00\x6d\x00\x75\x00\x63\x00\x68\x00\x61\x00\x07\x01" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_10 {
  meta:
    info = "do kurwy nędzy"
  strings:
    $utf8 = "\x64\x6f\x20\x6b\x75\x72\x77\x79\x20\x6e\xc4\x99\x64\x7a\x79" nocase fullword
    $wide = "\x64\x00\x6f\x00\x20\x00\x6b\x00\x75\x00\x72\x00\x77\x00\x79\x00\x20\x00\x6e\x00\x19\x01\x64\x00\x7a\x00\x79\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_11 {
  meta:
    info = "dupa"
  strings:
    $utf8 = "\x64\x75\x70\x61" nocase fullword
    $wide = "\x64\x00\x75\x00\x70\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_12 {
  meta:
    info = "dupek"
  strings:
    $utf8 = "\x64\x75\x70\x65\x6b" nocase fullword
    $wide = "\x64\x00\x75\x00\x70\x00\x65\x00\x6b\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_13 {
  meta:
    info = "duperele"
  strings:
    $utf8 = "\x64\x75\x70\x65\x72\x65\x6c\x65" nocase fullword
    $wide = "\x64\x00\x75\x00\x70\x00\x65\x00\x72\x00\x65\x00\x6c\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_14 {
  meta:
    info = "dziwka"
  strings:
    $utf8 = "\x64\x7a\x69\x77\x6b\x61" nocase fullword
    $wide = "\x64\x00\x7a\x00\x69\x00\x77\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_15 {
  meta:
    info = "fiut"
  strings:
    $utf8 = "\x66\x69\x75\x74" nocase fullword
    $wide = "\x66\x00\x69\x00\x75\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_18 {
  meta:
    info = "huj"
  strings:
    $utf8 = "\x68\x75\x6a" nocase fullword
    $wide = "\x68\x00\x75\x00\x6a\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_19 {
  meta:
    info = "ja pierdolę"
  strings:
    $utf8 = "\x6a\x61\x20\x70\x69\x65\x72\x64\x6f\x6c\xc4\x99" nocase fullword
    $wide = "\x6a\x00\x61\x00\x20\x00\x70\x00\x69\x00\x65\x00\x72\x00\x64\x00\x6f\x00\x6c\x00\x19\x01" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_24 {
  meta:
    info = "jebany"
  strings:
    $utf8 = "\x6a\x65\x62\x61\x6e\x79" nocase fullword
    $wide = "\x6a\x00\x65\x00\x62\x00\x61\x00\x6e\x00\x79\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_25 {
  meta:
    info = "jebać"
  strings:
    $utf8 = "\x6a\x65\x62\x61\xc4\x87" nocase fullword
    $wide = "\x6a\x00\x65\x00\x62\x00\x61\x00\x07\x01" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_26 {
  meta:
    info = "kurwa"
  strings:
    $utf8 = "\x6b\x75\x72\x77\x61" nocase fullword
    $wide = "\x6b\x00\x75\x00\x72\x00\x77\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_27 {
  meta:
    info = "kurwy"
  strings:
    $utf8 = "\x6b\x75\x72\x77\x79" nocase fullword
    $wide = "\x6b\x00\x75\x00\x72\x00\x77\x00\x79\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_28 {
  meta:
    info = "kutafon"
  strings:
    $utf8 = "\x6b\x75\x74\x61\x66\x6f\x6e" nocase fullword
    $wide = "\x6b\x00\x75\x00\x74\x00\x61\x00\x66\x00\x6f\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_29 {
  meta:
    info = "kutas"
  strings:
    $utf8 = "\x6b\x75\x74\x61\x73" nocase fullword
    $wide = "\x6b\x00\x75\x00\x74\x00\x61\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_30 {
  meta:
    info = "lizać pałę"
  strings:
    $utf8 = "\x6c\x69\x7a\x61\xc4\x87\x20\x70\x61\xc5\x82\xc4\x99" nocase fullword
    $wide = "\x6c\x00\x69\x00\x7a\x00\x61\x00\x07\x01\x20\x00\x70\x00\x61\x00\x42\x01\x19\x01" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_31 {
  meta:
    info = "obciągać chuja"
  strings:
    $utf8 = "\x6f\x62\x63\x69\xc4\x85\x67\x61\xc4\x87\x20\x63\x68\x75\x6a\x61" nocase fullword
    $wide = "\x6f\x00\x62\x00\x63\x00\x69\x00\x05\x01\x67\x00\x61\x00\x07\x01\x20\x00\x63\x00\x68\x00\x75\x00\x6a\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_32 {
  meta:
    info = "obciągać fiuta"
  strings:
    $utf8 = "\x6f\x62\x63\x69\xc4\x85\x67\x61\xc4\x87\x20\x66\x69\x75\x74\x61" nocase fullword
    $wide = "\x6f\x00\x62\x00\x63\x00\x69\x00\x05\x01\x67\x00\x61\x00\x07\x01\x20\x00\x66\x00\x69\x00\x75\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_33 {
  meta:
    info = "obciągać loda"
  strings:
    $utf8 = "\x6f\x62\x63\x69\xc4\x85\x67\x61\xc4\x87\x20\x6c\x6f\x64\x61" nocase fullword
    $wide = "\x6f\x00\x62\x00\x63\x00\x69\x00\x05\x01\x67\x00\x61\x00\x07\x01\x20\x00\x6c\x00\x6f\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_34 {
  meta:
    info = "pieprzyć"
  strings:
    $utf8 = "\x70\x69\x65\x70\x72\x7a\x79\xc4\x87" nocase fullword
    $wide = "\x70\x00\x69\x00\x65\x00\x70\x00\x72\x00\x7a\x00\x79\x00\x07\x01" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_35 {
  meta:
    info = "pierdolec"
  strings:
    $utf8 = "\x70\x69\x65\x72\x64\x6f\x6c\x65\x63" nocase fullword
    $wide = "\x70\x00\x69\x00\x65\x00\x72\x00\x64\x00\x6f\x00\x6c\x00\x65\x00\x63\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_36 {
  meta:
    info = "pierdolić"
  strings:
    $utf8 = "\x70\x69\x65\x72\x64\x6f\x6c\x69\xc4\x87" nocase fullword
    $wide = "\x70\x00\x69\x00\x65\x00\x72\x00\x64\x00\x6f\x00\x6c\x00\x69\x00\x07\x01" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_37 {
  meta:
    info = "pierdolnięty"
  strings:
    $utf8 = "\x70\x69\x65\x72\x64\x6f\x6c\x6e\x69\xc4\x99\x74\x79" nocase fullword
    $wide = "\x70\x00\x69\x00\x65\x00\x72\x00\x64\x00\x6f\x00\x6c\x00\x6e\x00\x69\x00\x19\x01\x74\x00\x79\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_38 {
  meta:
    info = "pierdoła"
  strings:
    $utf8 = "\x70\x69\x65\x72\x64\x6f\xc5\x82\x61" nocase fullword
    $wide = "\x70\x00\x69\x00\x65\x00\x72\x00\x64\x00\x6f\x00\x42\x01\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_39 {
  meta:
    info = "pierdzieć"
  strings:
    $utf8 = "\x70\x69\x65\x72\x64\x7a\x69\x65\xc4\x87" nocase fullword
    $wide = "\x70\x00\x69\x00\x65\x00\x72\x00\x64\x00\x7a\x00\x69\x00\x65\x00\x07\x01" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_40 {
  meta:
    info = "pizda"
  strings:
    $utf8 = "\x70\x69\x7a\x64\x61" nocase fullword
    $wide = "\x70\x00\x69\x00\x7a\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_41 {
  meta:
    info = "pojeb"
  strings:
    $utf8 = "\x70\x6f\x6a\x65\x62" nocase fullword
    $wide = "\x70\x00\x6f\x00\x6a\x00\x65\x00\x62\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_42 {
  meta:
    info = "popierdolony"
  strings:
    $utf8 = "\x70\x6f\x70\x69\x65\x72\x64\x6f\x6c\x6f\x6e\x79" nocase fullword
    $wide = "\x70\x00\x6f\x00\x70\x00\x69\x00\x65\x00\x72\x00\x64\x00\x6f\x00\x6c\x00\x6f\x00\x6e\x00\x79\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_43 {
  meta:
    info = "robic loda"
  strings:
    $utf8 = "\x72\x6f\x62\x69\x63\x20\x6c\x6f\x64\x61" nocase fullword
    $wide = "\x72\x00\x6f\x00\x62\x00\x69\x00\x63\x00\x20\x00\x6c\x00\x6f\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_44 {
  meta:
    info = "robić loda"
  strings:
    $utf8 = "\x72\x6f\x62\x69\xc4\x87\x20\x6c\x6f\x64\x61" nocase fullword
    $wide = "\x72\x00\x6f\x00\x62\x00\x69\x00\x07\x01\x20\x00\x6c\x00\x6f\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_45 {
  meta:
    info = "ruchać"
  strings:
    $utf8 = "\x72\x75\x63\x68\x61\xc4\x87" nocase fullword
    $wide = "\x72\x00\x75\x00\x63\x00\x68\x00\x61\x00\x07\x01" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_46 {
  meta:
    info = "rzygać"
  strings:
    $utf8 = "\x72\x7a\x79\x67\x61\xc4\x87" nocase fullword
    $wide = "\x72\x00\x7a\x00\x79\x00\x67\x00\x61\x00\x07\x01" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_47 {
  meta:
    info = "skurwysyn"
  strings:
    $utf8 = "\x73\x6b\x75\x72\x77\x79\x73\x79\x6e" nocase fullword
    $wide = "\x73\x00\x6b\x00\x75\x00\x72\x00\x77\x00\x79\x00\x73\x00\x79\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_50 {
  meta:
    info = "suka"
  strings:
    $utf8 = "\x73\x75\x6b\x61" nocase fullword
    $wide = "\x73\x00\x75\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_51 {
  meta:
    info = "syf"
  strings:
    $utf8 = "\x73\x79\x66" nocase fullword
    $wide = "\x73\x00\x79\x00\x66\x00" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_52 {
  meta:
    info = "wkurwiać"
  strings:
    $utf8 = "\x77\x6b\x75\x72\x77\x69\x61\xc4\x87" nocase fullword
    $wide = "\x77\x00\x6b\x00\x75\x00\x72\x00\x77\x00\x69\x00\x61\x00\x07\x01" nocase fullword
  condition:
    any of them
}
rule content_pl_language_nsfw_53 {
  meta:
    info = "zajebisty"
  strings:
    $utf8 = "\x7a\x61\x6a\x65\x62\x69\x73\x74\x79" nocase fullword
    $wide = "\x7a\x00\x61\x00\x6a\x00\x65\x00\x62\x00\x69\x00\x73\x00\x74\x00\x79\x00" nocase fullword
  condition:
    any of them
}

rule content_pl_language_nsfw_test {
  meta:
    info = "Test rule for pl language detection - UUID: A8B9C0D1-E2F3-44A5-B6C7-D8E9F0A1B2C3"
  strings:
    $ = "A8B9C0D1-E2F3-44A5-B6C7-D8E9F0A1B2C3" fullword wide ascii nocase
  condition:
    any of them
}
