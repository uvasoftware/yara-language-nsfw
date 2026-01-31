rule content_fi_language_nsfw_1 {
  meta:
    info = "alfred nussi"
  strings:
    $utf8 = "\x61\x6c\x66\x72\x65\x64\x20\x6e\x75\x73\x73\x69" nocase fullword
    $wide = "\x61\x00\x6c\x00\x66\x00\x72\x00\x65\x00\x64\x00\x20\x00\x6e\x00\x75\x00\x73\x00\x73\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_2 {
  meta:
    info = "bylsiä"
  strings:
    $utf8 = "\x62\x79\x6c\x73\x69\xc3\xa4" nocase fullword
    $wide = "\x62\x00\x79\x00\x6c\x00\x73\x00\x69\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_3 {
  meta:
    info = "haahka"
  strings:
    $utf8 = "\x68\x61\x61\x68\x6b\x61" nocase fullword
    $wide = "\x68\x00\x61\x00\x61\x00\x68\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_4 {
  meta:
    info = "haista paska"
  strings:
    $utf8 = "\x68\x61\x69\x73\x74\x61\x20\x70\x61\x73\x6b\x61" nocase fullword
    $wide = "\x68\x00\x61\x00\x69\x00\x73\x00\x74\x00\x61\x00\x20\x00\x70\x00\x61\x00\x73\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_5 {
  meta:
    info = "haista vittu"
  strings:
    $utf8 = "\x68\x61\x69\x73\x74\x61\x20\x76\x69\x74\x74\x75" nocase fullword
    $wide = "\x68\x00\x61\x00\x69\x00\x73\x00\x74\x00\x61\x00\x20\x00\x76\x00\x69\x00\x74\x00\x74\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_6 {
  meta:
    info = "hatullinen"
  strings:
    $utf8 = "\x68\x61\x74\x75\x6c\x6c\x69\x6e\x65\x6e" nocase fullword
    $wide = "\x68\x00\x61\x00\x74\x00\x75\x00\x6c\x00\x6c\x00\x69\x00\x6e\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_7 {
  meta:
    info = "helvetisti"
  strings:
    $utf8 = "\x68\x65\x6c\x76\x65\x74\x69\x73\x74\x69" nocase fullword
    $wide = "\x68\x00\x65\x00\x6c\x00\x76\x00\x65\x00\x74\x00\x69\x00\x73\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_8 {
  meta:
    info = "hevonkuusi"
  strings:
    $utf8 = "\x68\x65\x76\x6f\x6e\x6b\x75\x75\x73\x69" nocase fullword
    $wide = "\x68\x00\x65\x00\x76\x00\x6f\x00\x6e\x00\x6b\x00\x75\x00\x75\x00\x73\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_9 {
  meta:
    info = "hevonpaska"
  strings:
    $utf8 = "\x68\x65\x76\x6f\x6e\x70\x61\x73\x6b\x61" nocase fullword
    $wide = "\x68\x00\x65\x00\x76\x00\x6f\x00\x6e\x00\x70\x00\x61\x00\x73\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_10 {
  meta:
    info = "hevonperse"
  strings:
    $utf8 = "\x68\x65\x76\x6f\x6e\x70\x65\x72\x73\x65" nocase fullword
    $wide = "\x68\x00\x65\x00\x76\x00\x6f\x00\x6e\x00\x70\x00\x65\x00\x72\x00\x73\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_11 {
  meta:
    info = "hevonvittu"
  strings:
    $utf8 = "\x68\x65\x76\x6f\x6e\x76\x69\x74\x74\x75" nocase fullword
    $wide = "\x68\x00\x65\x00\x76\x00\x6f\x00\x6e\x00\x76\x00\x69\x00\x74\x00\x74\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_12 {
  meta:
    info = "hevonvitunperse"
  strings:
    $utf8 = "\x68\x65\x76\x6f\x6e\x76\x69\x74\x75\x6e\x70\x65\x72\x73\x65" nocase fullword
    $wide = "\x68\x00\x65\x00\x76\x00\x6f\x00\x6e\x00\x76\x00\x69\x00\x74\x00\x75\x00\x6e\x00\x70\x00\x65\x00\x72\x00\x73\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_13 {
  meta:
    info = "hitosti"
  strings:
    $utf8 = "\x68\x69\x74\x6f\x73\x74\x69" nocase fullword
    $wide = "\x68\x00\x69\x00\x74\x00\x6f\x00\x73\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_15 {
  meta:
    info = "huorata"
  strings:
    $utf8 = "\x68\x75\x6f\x72\x61\x74\x61" nocase fullword
    $wide = "\x68\x00\x75\x00\x6f\x00\x72\x00\x61\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_16 {
  meta:
    info = "hässiä"
  strings:
    $utf8 = "\x68\xc3\xa4\x73\x73\x69\xc3\xa4" nocase fullword
    $wide = "\x68\x00\xe4\x00\x73\x00\x73\x00\x69\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_17 {
  meta:
    info = "juosten kustu"
  strings:
    $utf8 = "\x6a\x75\x6f\x73\x74\x65\x6e\x20\x6b\x75\x73\x74\x75" nocase fullword
    $wide = "\x6a\x00\x75\x00\x6f\x00\x73\x00\x74\x00\x65\x00\x6e\x00\x20\x00\x6b\x00\x75\x00\x73\x00\x74\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_18 {
  meta:
    info = "jutku"
  strings:
    $utf8 = "\x6a\x75\x74\x6b\x75" nocase fullword
    $wide = "\x6a\x00\x75\x00\x74\x00\x6b\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_19 {
  meta:
    info = "jutsku"
  strings:
    $utf8 = "\x6a\x75\x74\x73\x6b\x75" nocase fullword
    $wide = "\x6a\x00\x75\x00\x74\x00\x73\x00\x6b\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_20 {
  meta:
    info = "kananpaska"
  strings:
    $utf8 = "\x6b\x61\x6e\x61\x6e\x70\x61\x73\x6b\x61" nocase fullword
    $wide = "\x6b\x00\x61\x00\x6e\x00\x61\x00\x6e\x00\x70\x00\x61\x00\x73\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_21 {
  meta:
    info = "koiranpaska"
  strings:
    $utf8 = "\x6b\x6f\x69\x72\x61\x6e\x70\x61\x73\x6b\x61" nocase fullword
    $wide = "\x6b\x00\x6f\x00\x69\x00\x72\x00\x61\x00\x6e\x00\x70\x00\x61\x00\x73\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_22 {
  meta:
    info = "kuin esterin perseestä"
  strings:
    $utf8 = "\x6b\x75\x69\x6e\x20\x65\x73\x74\x65\x72\x69\x6e\x20\x70\x65\x72\x73\x65\x65\x73\x74\xc3\xa4" nocase fullword
    $wide = "\x6b\x00\x75\x00\x69\x00\x6e\x00\x20\x00\x65\x00\x73\x00\x74\x00\x65\x00\x72\x00\x69\x00\x6e\x00\x20\x00\x70\x00\x65\x00\x72\x00\x73\x00\x65\x00\x65\x00\x73\x00\x74\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_23 {
  meta:
    info = "kulli"
  strings:
    $utf8 = "\x6b\x75\x6c\x6c\x69" nocase fullword
    $wide = "\x6b\x00\x75\x00\x6c\x00\x6c\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_24 {
  meta:
    info = "kullinluikaus"
  strings:
    $utf8 = "\x6b\x75\x6c\x6c\x69\x6e\x6c\x75\x69\x6b\x61\x75\x73" nocase fullword
    $wide = "\x6b\x00\x75\x00\x6c\x00\x6c\x00\x69\x00\x6e\x00\x6c\x00\x75\x00\x69\x00\x6b\x00\x61\x00\x75\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_25 {
  meta:
    info = "kuppainen"
  strings:
    $utf8 = "\x6b\x75\x70\x70\x61\x69\x6e\x65\x6e" nocase fullword
    $wide = "\x6b\x00\x75\x00\x70\x00\x70\x00\x61\x00\x69\x00\x6e\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_26 {
  meta:
    info = "kusaista"
  strings:
    $utf8 = "\x6b\x75\x73\x61\x69\x73\x74\x61" nocase fullword
    $wide = "\x6b\x00\x75\x00\x73\x00\x61\x00\x69\x00\x73\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_27 {
  meta:
    info = "kuseksia"
  strings:
    $utf8 = "\x6b\x75\x73\x65\x6b\x73\x69\x61" nocase fullword
    $wide = "\x6b\x00\x75\x00\x73\x00\x65\x00\x6b\x00\x73\x00\x69\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_28 {
  meta:
    info = "kusettaa"
  strings:
    $utf8 = "\x6b\x75\x73\x65\x74\x74\x61\x61" nocase fullword
    $wide = "\x6b\x00\x75\x00\x73\x00\x65\x00\x74\x00\x74\x00\x61\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_29 {
  meta:
    info = "kusi"
  strings:
    $utf8 = "\x6b\x75\x73\x69" nocase fullword
    $wide = "\x6b\x00\x75\x00\x73\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_30 {
  meta:
    info = "kusipää"
  strings:
    $utf8 = "\x6b\x75\x73\x69\x70\xc3\xa4\xc3\xa4" nocase fullword
    $wide = "\x6b\x00\x75\x00\x73\x00\x69\x00\x70\x00\xe4\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_31 {
  meta:
    info = "kusta"
  strings:
    $utf8 = "\x6b\x75\x73\x74\x61" nocase fullword
    $wide = "\x6b\x00\x75\x00\x73\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_32 {
  meta:
    info = "kyrpiintynyt"
  strings:
    $utf8 = "\x6b\x79\x72\x70\x69\x69\x6e\x74\x79\x6e\x79\x74" nocase fullword
    $wide = "\x6b\x00\x79\x00\x72\x00\x70\x00\x69\x00\x69\x00\x6e\x00\x74\x00\x79\x00\x6e\x00\x79\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_33 {
  meta:
    info = "kyrpiintyä"
  strings:
    $utf8 = "\x6b\x79\x72\x70\x69\x69\x6e\x74\x79\xc3\xa4" nocase fullword
    $wide = "\x6b\x00\x79\x00\x72\x00\x70\x00\x69\x00\x69\x00\x6e\x00\x74\x00\x79\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_34 {
  meta:
    info = "kyrpiä"
  strings:
    $utf8 = "\x6b\x79\x72\x70\x69\xc3\xa4" nocase fullword
    $wide = "\x6b\x00\x79\x00\x72\x00\x70\x00\x69\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_35 {
  meta:
    info = "kyrpä"
  strings:
    $utf8 = "\x6b\x79\x72\x70\xc3\xa4" nocase fullword
    $wide = "\x6b\x00\x79\x00\x72\x00\x70\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_36 {
  meta:
    info = "kyrpänaama"
  strings:
    $utf8 = "\x6b\x79\x72\x70\xc3\xa4\x6e\x61\x61\x6d\x61" nocase fullword
    $wide = "\x6b\x00\x79\x00\x72\x00\x70\x00\xe4\x00\x6e\x00\x61\x00\x61\x00\x6d\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_37 {
  meta:
    info = "kyrvitys"
  strings:
    $utf8 = "\x6b\x79\x72\x76\x69\x74\x79\x73" nocase fullword
    $wide = "\x6b\x00\x79\x00\x72\x00\x76\x00\x69\x00\x74\x00\x79\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_38 {
  meta:
    info = "lahtari"
  strings:
    $utf8 = "\x6c\x61\x68\x74\x61\x72\x69" nocase fullword
    $wide = "\x6c\x00\x61\x00\x68\x00\x74\x00\x61\x00\x72\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_39 {
  meta:
    info = "lutka"
  strings:
    $utf8 = "\x6c\x75\x74\x6b\x61" nocase fullword
    $wide = "\x6c\x00\x75\x00\x74\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_40 {
  meta:
    info = "molo"
  strings:
    $utf8 = "\x6d\x6f\x6c\x6f" nocase fullword
    $wide = "\x6d\x00\x6f\x00\x6c\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_41 {
  meta:
    info = "molopää"
  strings:
    $utf8 = "\x6d\x6f\x6c\x6f\x70\xc3\xa4\xc3\xa4" nocase fullword
    $wide = "\x6d\x00\x6f\x00\x6c\x00\x6f\x00\x70\x00\xe4\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_42 {
  meta:
    info = "mulkero"
  strings:
    $utf8 = "\x6d\x75\x6c\x6b\x65\x72\x6f" nocase fullword
    $wide = "\x6d\x00\x75\x00\x6c\x00\x6b\x00\x65\x00\x72\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_43 {
  meta:
    info = "mulkku"
  strings:
    $utf8 = "\x6d\x75\x6c\x6b\x6b\x75" nocase fullword
    $wide = "\x6d\x00\x75\x00\x6c\x00\x6b\x00\x6b\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_44 {
  meta:
    info = "mulkvisti"
  strings:
    $utf8 = "\x6d\x75\x6c\x6b\x76\x69\x73\x74\x69" nocase fullword
    $wide = "\x6d\x00\x75\x00\x6c\x00\x6b\x00\x76\x00\x69\x00\x73\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_45 {
  meta:
    info = "munapää"
  strings:
    $utf8 = "\x6d\x75\x6e\x61\x70\xc3\xa4\xc3\xa4" nocase fullword
    $wide = "\x6d\x00\x75\x00\x6e\x00\x61\x00\x70\x00\xe4\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_46 {
  meta:
    info = "munaton"
  strings:
    $utf8 = "\x6d\x75\x6e\x61\x74\x6f\x6e" nocase fullword
    $wide = "\x6d\x00\x75\x00\x6e\x00\x61\x00\x74\x00\x6f\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_47 {
  meta:
    info = "mutakuono"
  strings:
    $utf8 = "\x6d\x75\x74\x61\x6b\x75\x6f\x6e\x6f" nocase fullword
    $wide = "\x6d\x00\x75\x00\x74\x00\x61\x00\x6b\x00\x75\x00\x6f\x00\x6e\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_48 {
  meta:
    info = "mutiainen"
  strings:
    $utf8 = "\x6d\x75\x74\x69\x61\x69\x6e\x65\x6e" nocase fullword
    $wide = "\x6d\x00\x75\x00\x74\x00\x69\x00\x61\x00\x69\x00\x6e\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_49 {
  meta:
    info = "naida"
  strings:
    $utf8 = "\x6e\x61\x69\x64\x61" nocase fullword
    $wide = "\x6e\x00\x61\x00\x69\x00\x64\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_50 {
  meta:
    info = "nainti"
  strings:
    $utf8 = "\x6e\x61\x69\x6e\x74\x69" nocase fullword
    $wide = "\x6e\x00\x61\x00\x69\x00\x6e\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_51 {
  meta:
    info = "narttu"
  strings:
    $utf8 = "\x6e\x61\x72\x74\x74\x75" nocase fullword
    $wide = "\x6e\x00\x61\x00\x72\x00\x74\x00\x74\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_52 {
  meta:
    info = "neekeri"
  strings:
    $utf8 = "\x6e\x65\x65\x6b\x65\x72\x69" nocase fullword
    $wide = "\x6e\x00\x65\x00\x65\x00\x6b\x00\x65\x00\x72\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_53 {
  meta:
    info = "nekru"
  strings:
    $utf8 = "\x6e\x65\x6b\x72\x75" nocase fullword
    $wide = "\x6e\x00\x65\x00\x6b\x00\x72\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_54 {
  meta:
    info = "nuolla persettä"
  strings:
    $utf8 = "\x6e\x75\x6f\x6c\x6c\x61\x20\x70\x65\x72\x73\x65\x74\x74\xc3\xa4" nocase fullword
    $wide = "\x6e\x00\x75\x00\x6f\x00\x6c\x00\x6c\x00\x61\x00\x20\x00\x70\x00\x65\x00\x72\x00\x73\x00\x65\x00\x74\x00\x74\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_55 {
  meta:
    info = "nussia"
  strings:
    $utf8 = "\x6e\x75\x73\x73\x69\x61" nocase fullword
    $wide = "\x6e\x00\x75\x00\x73\x00\x73\x00\x69\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_56 {
  meta:
    info = "nussija"
  strings:
    $utf8 = "\x6e\x75\x73\x73\x69\x6a\x61" nocase fullword
    $wide = "\x6e\x00\x75\x00\x73\x00\x73\x00\x69\x00\x6a\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_57 {
  meta:
    info = "nussinta"
  strings:
    $utf8 = "\x6e\x75\x73\x73\x69\x6e\x74\x61" nocase fullword
    $wide = "\x6e\x00\x75\x00\x73\x00\x73\x00\x69\x00\x6e\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_58 {
  meta:
    info = "paljaalla"
  strings:
    $utf8 = "\x70\x61\x6c\x6a\x61\x61\x6c\x6c\x61" nocase fullword
    $wide = "\x70\x00\x61\x00\x6c\x00\x6a\x00\x61\x00\x61\x00\x6c\x00\x6c\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_59 {
  meta:
    info = "palli"
  strings:
    $utf8 = "\x70\x61\x6c\x6c\x69" nocase fullword
    $wide = "\x70\x00\x61\x00\x6c\x00\x6c\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_60 {
  meta:
    info = "pallit"
  strings:
    $utf8 = "\x70\x61\x6c\x6c\x69\x74" nocase fullword
    $wide = "\x70\x00\x61\x00\x6c\x00\x6c\x00\x69\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_61 {
  meta:
    info = "paneskella"
  strings:
    $utf8 = "\x70\x61\x6e\x65\x73\x6b\x65\x6c\x6c\x61" nocase fullword
    $wide = "\x70\x00\x61\x00\x6e\x00\x65\x00\x73\x00\x6b\x00\x65\x00\x6c\x00\x6c\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_62 {
  meta:
    info = "panettaa"
  strings:
    $utf8 = "\x70\x61\x6e\x65\x74\x74\x61\x61" nocase fullword
    $wide = "\x70\x00\x61\x00\x6e\x00\x65\x00\x74\x00\x74\x00\x61\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_63 {
  meta:
    info = "pano"
  strings:
    $utf8 = "\x70\x61\x6e\x6f" nocase fullword
    $wide = "\x70\x00\x61\x00\x6e\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_64 {
  meta:
    info = "pantava"
  strings:
    $utf8 = "\x70\x61\x6e\x74\x61\x76\x61" nocase fullword
    $wide = "\x70\x00\x61\x00\x6e\x00\x74\x00\x61\x00\x76\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_65 {
  meta:
    info = "paska"
  strings:
    $utf8 = "\x70\x61\x73\x6b\x61" nocase fullword
    $wide = "\x70\x00\x61\x00\x73\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_66 {
  meta:
    info = "paskainen"
  strings:
    $utf8 = "\x70\x61\x73\x6b\x61\x69\x6e\x65\x6e" nocase fullword
    $wide = "\x70\x00\x61\x00\x73\x00\x6b\x00\x61\x00\x69\x00\x6e\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_67 {
  meta:
    info = "paskamainen"
  strings:
    $utf8 = "\x70\x61\x73\x6b\x61\x6d\x61\x69\x6e\x65\x6e" nocase fullword
    $wide = "\x70\x00\x61\x00\x73\x00\x6b\x00\x61\x00\x6d\x00\x61\x00\x69\x00\x6e\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_68 {
  meta:
    info = "paskanmarjat"
  strings:
    $utf8 = "\x70\x61\x73\x6b\x61\x6e\x6d\x61\x72\x6a\x61\x74" nocase fullword
    $wide = "\x70\x00\x61\x00\x73\x00\x6b\x00\x61\x00\x6e\x00\x6d\x00\x61\x00\x72\x00\x6a\x00\x61\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_69 {
  meta:
    info = "paskantaa"
  strings:
    $utf8 = "\x70\x61\x73\x6b\x61\x6e\x74\x61\x61" nocase fullword
    $wide = "\x70\x00\x61\x00\x73\x00\x6b\x00\x61\x00\x6e\x00\x74\x00\x61\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_70 {
  meta:
    info = "paskapuhe"
  strings:
    $utf8 = "\x70\x61\x73\x6b\x61\x70\x75\x68\x65" nocase fullword
    $wide = "\x70\x00\x61\x00\x73\x00\x6b\x00\x61\x00\x70\x00\x75\x00\x68\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_71 {
  meta:
    info = "paskapää"
  strings:
    $utf8 = "\x70\x61\x73\x6b\x61\x70\xc3\xa4\xc3\xa4" nocase fullword
    $wide = "\x70\x00\x61\x00\x73\x00\x6b\x00\x61\x00\x70\x00\xe4\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_72 {
  meta:
    info = "paskattaa"
  strings:
    $utf8 = "\x70\x61\x73\x6b\x61\x74\x74\x61\x61" nocase fullword
    $wide = "\x70\x00\x61\x00\x73\x00\x6b\x00\x61\x00\x74\x00\x74\x00\x61\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_73 {
  meta:
    info = "paskiainen"
  strings:
    $utf8 = "\x70\x61\x73\x6b\x69\x61\x69\x6e\x65\x6e" nocase fullword
    $wide = "\x70\x00\x61\x00\x73\x00\x6b\x00\x69\x00\x61\x00\x69\x00\x6e\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_74 {
  meta:
    info = "paskoa"
  strings:
    $utf8 = "\x70\x61\x73\x6b\x6f\x61" nocase fullword
    $wide = "\x70\x00\x61\x00\x73\x00\x6b\x00\x6f\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_75 {
  meta:
    info = "pehko"
  strings:
    $utf8 = "\x70\x65\x68\x6b\x6f" nocase fullword
    $wide = "\x70\x00\x65\x00\x68\x00\x6b\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_76 {
  meta:
    info = "pentele"
  strings:
    $utf8 = "\x70\x65\x6e\x74\x65\x6c\x65" nocase fullword
    $wide = "\x70\x00\x65\x00\x6e\x00\x74\x00\x65\x00\x6c\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_77 {
  meta:
    info = "perkele"
  strings:
    $utf8 = "\x70\x65\x72\x6b\x65\x6c\x65" nocase fullword
    $wide = "\x70\x00\x65\x00\x72\x00\x6b\x00\x65\x00\x6c\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_78 {
  meta:
    info = "perkeleesti"
  strings:
    $utf8 = "\x70\x65\x72\x6b\x65\x6c\x65\x65\x73\x74\x69" nocase fullword
    $wide = "\x70\x00\x65\x00\x72\x00\x6b\x00\x65\x00\x6c\x00\x65\x00\x65\x00\x73\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_79 {
  meta:
    info = "persaukinen"
  strings:
    $utf8 = "\x70\x65\x72\x73\x61\x75\x6b\x69\x6e\x65\x6e" nocase fullword
    $wide = "\x70\x00\x65\x00\x72\x00\x73\x00\x61\x00\x75\x00\x6b\x00\x69\x00\x6e\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_80 {
  meta:
    info = "perse"
  strings:
    $utf8 = "\x70\x65\x72\x73\x65" nocase fullword
    $wide = "\x70\x00\x65\x00\x72\x00\x73\x00\x65\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_81 {
  meta:
    info = "perseennuolija"
  strings:
    $utf8 = "\x70\x65\x72\x73\x65\x65\x6e\x6e\x75\x6f\x6c\x69\x6a\x61" nocase fullword
    $wide = "\x70\x00\x65\x00\x72\x00\x73\x00\x65\x00\x65\x00\x6e\x00\x6e\x00\x75\x00\x6f\x00\x6c\x00\x69\x00\x6a\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_82 {
  meta:
    info = "perseet olalla"
  strings:
    $utf8 = "\x70\x65\x72\x73\x65\x65\x74\x20\x6f\x6c\x61\x6c\x6c\x61" nocase fullword
    $wide = "\x70\x00\x65\x00\x72\x00\x73\x00\x65\x00\x65\x00\x74\x00\x20\x00\x6f\x00\x6c\x00\x61\x00\x6c\x00\x6c\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_83 {
  meta:
    info = "persereikä"
  strings:
    $utf8 = "\x70\x65\x72\x73\x65\x72\x65\x69\x6b\xc3\xa4" nocase fullword
    $wide = "\x70\x00\x65\x00\x72\x00\x73\x00\x65\x00\x72\x00\x65\x00\x69\x00\x6b\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_84 {
  meta:
    info = "perseääliö"
  strings:
    $utf8 = "\x70\x65\x72\x73\x65\xc3\xa4\xc3\xa4\x6c\x69\xc3\xb6" nocase fullword
    $wide = "\x70\x00\x65\x00\x72\x00\x73\x00\x65\x00\xe4\x00\xe4\x00\x6c\x00\x69\x00\xf6\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_85 {
  meta:
    info = "persläpi"
  strings:
    $utf8 = "\x70\x65\x72\x73\x6c\xc3\xa4\x70\x69" nocase fullword
    $wide = "\x70\x00\x65\x00\x72\x00\x73\x00\x6c\x00\xe4\x00\x70\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_86 {
  meta:
    info = "perspano"
  strings:
    $utf8 = "\x70\x65\x72\x73\x70\x61\x6e\x6f" nocase fullword
    $wide = "\x70\x00\x65\x00\x72\x00\x73\x00\x70\x00\x61\x00\x6e\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_87 {
  meta:
    info = "persvako"
  strings:
    $utf8 = "\x70\x65\x72\x73\x76\x61\x6b\x6f" nocase fullword
    $wide = "\x70\x00\x65\x00\x72\x00\x73\x00\x76\x00\x61\x00\x6b\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_88 {
  meta:
    info = "pilkunnussija"
  strings:
    $utf8 = "\x70\x69\x6c\x6b\x75\x6e\x6e\x75\x73\x73\x69\x6a\x61" nocase fullword
    $wide = "\x70\x00\x69\x00\x6c\x00\x6b\x00\x75\x00\x6e\x00\x6e\x00\x75\x00\x73\x00\x73\x00\x69\x00\x6a\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_89 {
  meta:
    info = "pillu"
  strings:
    $utf8 = "\x70\x69\x6c\x6c\x75" nocase fullword
    $wide = "\x70\x00\x69\x00\x6c\x00\x6c\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_90 {
  meta:
    info = "pillut"
  strings:
    $utf8 = "\x70\x69\x6c\x6c\x75\x74" nocase fullword
    $wide = "\x70\x00\x69\x00\x6c\x00\x6c\x00\x75\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_92 {
  meta:
    info = "pistää"
  strings:
    $utf8 = "\x70\x69\x73\x74\xc3\xa4\xc3\xa4" nocase fullword
    $wide = "\x70\x00\x69\x00\x73\x00\x74\x00\xe4\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_93 {
  meta:
    info = "pyllyvako"
  strings:
    $utf8 = "\x70\x79\x6c\x6c\x79\x76\x61\x6b\x6f" nocase fullword
    $wide = "\x70\x00\x79\x00\x6c\x00\x6c\x00\x79\x00\x76\x00\x61\x00\x6b\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_94 {
  meta:
    info = "reva"
  strings:
    $utf8 = "\x72\x65\x76\x61" nocase fullword
    $wide = "\x72\x00\x65\x00\x76\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_95 {
  meta:
    info = "ripsipiirakka"
  strings:
    $utf8 = "\x72\x69\x70\x73\x69\x70\x69\x69\x72\x61\x6b\x6b\x61" nocase fullword
    $wide = "\x72\x00\x69\x00\x70\x00\x73\x00\x69\x00\x70\x00\x69\x00\x69\x00\x72\x00\x61\x00\x6b\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_96 {
  meta:
    info = "runkata"
  strings:
    $utf8 = "\x72\x75\x6e\x6b\x61\x74\x61" nocase fullword
    $wide = "\x72\x00\x75\x00\x6e\x00\x6b\x00\x61\x00\x74\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_97 {
  meta:
    info = "runkkari"
  strings:
    $utf8 = "\x72\x75\x6e\x6b\x6b\x61\x72\x69" nocase fullword
    $wide = "\x72\x00\x75\x00\x6e\x00\x6b\x00\x6b\x00\x61\x00\x72\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_98 {
  meta:
    info = "runkkaus"
  strings:
    $utf8 = "\x72\x75\x6e\x6b\x6b\x61\x75\x73" nocase fullword
    $wide = "\x72\x00\x75\x00\x6e\x00\x6b\x00\x6b\x00\x61\x00\x75\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_99 {
  meta:
    info = "runkku"
  strings:
    $utf8 = "\x72\x75\x6e\x6b\x6b\x75" nocase fullword
    $wide = "\x72\x00\x75\x00\x6e\x00\x6b\x00\x6b\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_100 {
  meta:
    info = "ryssä"
  strings:
    $utf8 = "\x72\x79\x73\x73\xc3\xa4" nocase fullword
    $wide = "\x72\x00\x79\x00\x73\x00\x73\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_101 {
  meta:
    info = "rättipää"
  strings:
    $utf8 = "\x72\xc3\xa4\x74\x74\x69\x70\xc3\xa4\xc3\xa4" nocase fullword
    $wide = "\x72\x00\xe4\x00\x74\x00\x74\x00\x69\x00\x70\x00\xe4\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_102 {
  meta:
    info = "saatanasti"
  strings:
    $utf8 = "\x73\x61\x61\x74\x61\x6e\x61\x73\x74\x69" nocase fullword
    $wide = "\x73\x00\x61\x00\x61\x00\x74\x00\x61\x00\x6e\x00\x61\x00\x73\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_103 {
  meta:
    info = "suklaaosasto"
  strings:
    $utf8 = "\x73\x75\x6b\x6c\x61\x61\x6f\x73\x61\x73\x74\x6f" nocase fullword
    $wide = "\x73\x00\x75\x00\x6b\x00\x6c\x00\x61\x00\x61\x00\x6f\x00\x73\x00\x61\x00\x73\x00\x74\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_104 {
  meta:
    info = "toosa"
  strings:
    $utf8 = "\x74\x6f\x6f\x73\x61" nocase fullword
    $wide = "\x74\x00\x6f\x00\x6f\x00\x73\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_105 {
  meta:
    info = "tuhkaluukku"
  strings:
    $utf8 = "\x74\x75\x68\x6b\x61\x6c\x75\x75\x6b\x6b\x75" nocase fullword
    $wide = "\x74\x00\x75\x00\x68\x00\x6b\x00\x61\x00\x6c\x00\x75\x00\x75\x00\x6b\x00\x6b\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_106 {
  meta:
    info = "tumputtaa"
  strings:
    $utf8 = "\x74\x75\x6d\x70\x75\x74\x74\x61\x61" nocase fullword
    $wide = "\x74\x00\x75\x00\x6d\x00\x70\x00\x75\x00\x74\x00\x74\x00\x61\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_107 {
  meta:
    info = "turpasauna"
  strings:
    $utf8 = "\x74\x75\x72\x70\x61\x73\x61\x75\x6e\x61" nocase fullword
    $wide = "\x74\x00\x75\x00\x72\x00\x70\x00\x61\x00\x73\x00\x61\x00\x75\x00\x6e\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_108 {
  meta:
    info = "tussu"
  strings:
    $utf8 = "\x74\x75\x73\x73\x75" nocase fullword
    $wide = "\x74\x00\x75\x00\x73\x00\x73\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_109 {
  meta:
    info = "tussukka"
  strings:
    $utf8 = "\x74\x75\x73\x73\x75\x6b\x6b\x61" nocase fullword
    $wide = "\x74\x00\x75\x00\x73\x00\x73\x00\x75\x00\x6b\x00\x6b\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_110 {
  meta:
    info = "tussut"
  strings:
    $utf8 = "\x74\x75\x73\x73\x75\x74" nocase fullword
    $wide = "\x74\x00\x75\x00\x73\x00\x73\x00\x75\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_111 {
  meta:
    info = "vakipano"
  strings:
    $utf8 = "\x76\x61\x6b\x69\x70\x61\x6e\x6f" nocase fullword
    $wide = "\x76\x00\x61\x00\x6b\x00\x69\x00\x70\x00\x61\x00\x6e\x00\x6f\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_112 {
  meta:
    info = "vetää käteen"
  strings:
    $utf8 = "\x76\x65\x74\xc3\xa4\xc3\xa4\x20\x6b\xc3\xa4\x74\x65\x65\x6e" nocase fullword
    $wide = "\x76\x00\x65\x00\x74\x00\xe4\x00\xe4\x00\x20\x00\x6b\x00\xe4\x00\x74\x00\x65\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_113 {
  meta:
    info = "vittu"
  strings:
    $utf8 = "\x76\x69\x74\x74\x75" nocase fullword
    $wide = "\x76\x00\x69\x00\x74\x00\x74\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_114 {
  meta:
    info = "vittuilla"
  strings:
    $utf8 = "\x76\x69\x74\x74\x75\x69\x6c\x6c\x61" nocase fullword
    $wide = "\x76\x00\x69\x00\x74\x00\x74\x00\x75\x00\x69\x00\x6c\x00\x6c\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_115 {
  meta:
    info = "vittuilu"
  strings:
    $utf8 = "\x76\x69\x74\x74\x75\x69\x6c\x75" nocase fullword
    $wide = "\x76\x00\x69\x00\x74\x00\x74\x00\x75\x00\x69\x00\x6c\x00\x75\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_116 {
  meta:
    info = "vittumainen"
  strings:
    $utf8 = "\x76\x69\x74\x74\x75\x6d\x61\x69\x6e\x65\x6e" nocase fullword
    $wide = "\x76\x00\x69\x00\x74\x00\x74\x00\x75\x00\x6d\x00\x61\x00\x69\x00\x6e\x00\x65\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_117 {
  meta:
    info = "vittuuntua"
  strings:
    $utf8 = "\x76\x69\x74\x74\x75\x75\x6e\x74\x75\x61" nocase fullword
    $wide = "\x76\x00\x69\x00\x74\x00\x74\x00\x75\x00\x75\x00\x6e\x00\x74\x00\x75\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_118 {
  meta:
    info = "vittuuntunut"
  strings:
    $utf8 = "\x76\x69\x74\x74\x75\x75\x6e\x74\x75\x6e\x75\x74" nocase fullword
    $wide = "\x76\x00\x69\x00\x74\x00\x74\x00\x75\x00\x75\x00\x6e\x00\x74\x00\x75\x00\x6e\x00\x75\x00\x74\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_119 {
  meta:
    info = "vitun"
  strings:
    $utf8 = "\x76\x69\x74\x75\x6e" nocase fullword
    $wide = "\x76\x00\x69\x00\x74\x00\x75\x00\x6e\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_120 {
  meta:
    info = "vitusti"
  strings:
    $utf8 = "\x76\x69\x74\x75\x73\x74\x69" nocase fullword
    $wide = "\x76\x00\x69\x00\x74\x00\x75\x00\x73\x00\x74\x00\x69\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_121 {
  meta:
    info = "vituttaa"
  strings:
    $utf8 = "\x76\x69\x74\x75\x74\x74\x61\x61" nocase fullword
    $wide = "\x76\x00\x69\x00\x74\x00\x75\x00\x74\x00\x74\x00\x61\x00\x61\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_122 {
  meta:
    info = "vitutus"
  strings:
    $utf8 = "\x76\x69\x74\x75\x74\x75\x73" nocase fullword
    $wide = "\x76\x00\x69\x00\x74\x00\x75\x00\x74\x00\x75\x00\x73\x00" nocase fullword
  condition:
    any of them
}
rule content_fi_language_nsfw_123 {
  meta:
    info = "äpärä"
  strings:
    $utf8 = "\xc3\xa4\x70\xc3\xa4\x72\xc3\xa4" nocase fullword
    $wide = "\xe4\x00\x70\x00\xe4\x00\x72\x00\xe4\x00" nocase fullword
  condition:
    any of them
}
