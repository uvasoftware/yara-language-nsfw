
rule content_ar_language_nsfw_1 {
  meta:
    info = "كس"
  strings:
    $utf8 = "\xd9\x83\xd8\xb3" nocase
    $cp1256 = "\xdf\xd3" nocase
    $wide = "\x643\x00\x633\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_2 {
  meta:
    info = "زب"
  strings:
    $utf8 = "\xd8\xb2\xd8\xa8" nocase
    $cp1256 = "\xd2\xc8" nocase
    $wide = "\x632\x00\x628\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_3 {
  meta:
    info = "طيز"
  strings:
    $utf8 = "\xd8\xb7\xd9\x8a\xd8\xb2" nocase
    $cp1256 = "\xd8\xed\xd2" nocase
    $wide = "\x637\x00\x64a\x00\x632\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_4 {
  meta:
    info = "شرموطة"
  strings:
    $utf8 = "\xd8\xb4\xd8\xb1\xd9\x85\xd9\x88\xd8\xb7\xd8\xa9" nocase
    $cp1256 = "\xd4\xd1\xe3\xe6\xd8\xc9" nocase
    $wide = "\x634\x00\x631\x00\x645\x00\x648\x00\x637\x00\x629\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_5 {
  meta:
    info = "عاهرة"
  strings:
    $utf8 = "\xd8\xb9\xd8\xa7\xd9\x87\xd8\xb1\xd8\xa9" nocase
    $cp1256 = "\xda\xc7\xe5\xd1\xc9" nocase
    $wide = "\x639\x00\x627\x00\x647\x00\x631\x00\x629\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_6 {
  meta:
    info = "قحبة"
  strings:
    $utf8 = "\xd9\x82\xd8\xad\xd8\xa8\xd8\xa9" nocase
    $cp1256 = "\xde\xcd\xc8\xc9" nocase
    $wide = "\x642\x00\x62d\x00\x628\x00\x629\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_7 {
  meta:
    info = "منيوك"
  strings:
    $utf8 = "\xd9\x85\xd9\x86\xd9\x8a\xd9\x88\xd9\x83" nocase
    $cp1256 = "\xe3\xe4\xed\xe6\xdf" nocase
    $wide = "\x645\x00\x646\x00\x64a\x00\x648\x00\x643\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_8 {
  meta:
    info = "نيك"
  strings:
    $utf8 = "\xd9\x86\xd9\x8a\xd9\x83" nocase
    $cp1256 = "\xe4\xed\xdf" nocase
    $wide = "\x646\x00\x64a\x00\x643\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_9 {
  meta:
    info = "ينيك"
  strings:
    $utf8 = "\xd9\x8a\xd9\x86\xd9\x8a\xd9\x83" nocase
    $cp1256 = "\xed\xe4\xed\xdf" nocase
    $wide = "\x64a\x00\x646\x00\x64a\x00\x643\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_10 {
  meta:
    info = "كسمك"
  strings:
    $utf8 = "\xd9\x83\xd8\xb3\xd9\x85\xd9\x83" nocase
    $cp1256 = "\xdf\xd3\xe3\xdf" nocase
    $wide = "\x643\x00\x633\x00\x645\x00\x643\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_11 {
  meta:
    info = "ابن الشرموطة"
  strings:
    $utf8 = "\xd8\xa7\xd8\xa8\xd9\x86\x20\xd8\xa7\xd9\x84\xd8\xb4\xd8\xb1\xd9\x85\xd9\x88\xd8\xb7\xd8\xa9" nocase
    $cp1256 = "\xc7\xc8\xe4\x20\xc7\xe1\xd4\xd1\xe3\xe6\xd8\xc9" nocase
    $wide = "\x627\x00\x628\x00\x646\x00\x20\x00\x627\x00\x644\x00\x634\x00\x631\x00\x645\x00\x648\x00\x637\x00\x629\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_12 {
  meta:
    info = "ابن القحبة"
  strings:
    $utf8 = "\xd8\xa7\xd8\xa8\xd9\x86\x20\xd8\xa7\xd9\x84\xd9\x82\xd8\xad\xd8\xa8\xd8\xa9" nocase
    $cp1256 = "\xc7\xc8\xe4\x20\xc7\xe1\xde\xcd\xc8\xc9" nocase
    $wide = "\x627\x00\x628\x00\x646\x00\x20\x00\x627\x00\x644\x00\x642\x00\x62d\x00\x628\x00\x629\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_13 {
  meta:
    info = "خول"
  strings:
    $utf8 = "\xd8\xae\xd9\x88\xd9\x84" nocase
    $cp1256 = "\xce\xe6\xe1" nocase
    $wide = "\x62e\x00\x648\x00\x644\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_16 {
  meta:
    info = "متناك"
  strings:
    $utf8 = "\xd9\x85\xd8\xaa\xd9\x86\xd8\xa7\xd9\x83" nocase
    $cp1256 = "\xe3\xca\xe4\xc7\xdf" nocase
    $wide = "\x645\x00\x62a\x00\x646\x00\x627\x00\x643\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_22 {
  meta:
    info = "خرا"
  strings:
    $utf8 = "\xd8\xae\xd8\xb1\xd8\xa7" nocase
    $cp1256 = "\xce\xd1\xc7" nocase
    $wide = "\x62e\x00\x631\x00\x627\x00" nocase
  condition:
    any of them
}

rule content_ar_language_nsfw_25 {
  meta:
    info = "ديوث"
  strings:
    $utf8 = "\xd8\xaf\xd9\x8a\xd9\x88\xd8\xab" nocase
    $cp1256 = "\xcf\xed\xe6\xcb" nocase
    $wide = "\x62f\x00\x64a\x00\x648\x00\x62b\x00" nocase
  condition:
    any of them
}

