
rule content_ar_language_nsfw_1 {
  meta:
    info = "كس"
  strings:
    $utf8 = "\xd9\x83\xd8\xb3" nocase fullword
    $cp1256 = "\xdf\xd3" nocase fullword
    $wide = "\x43\x06\x33\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_2 {
  meta:
    info = "زب"
  strings:
    $utf8 = "\xd8\xb2\xd8\xa8" nocase fullword
    $cp1256 = "\xd2\xc8" nocase fullword
    $wide = "\x32\x06\x28\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_3 {
  meta:
    info = "طيز"
  strings:
    $utf8 = "\xd8\xb7\xd9\x8a\xd8\xb2" nocase fullword
    $cp1256 = "\xd8\xed\xd2" nocase fullword
    $wide = "\x37\x06\x4a\x06\x32\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_4 {
  meta:
    info = "شرموطة"
  strings:
    $utf8 = "\xd8\xb4\xd8\xb1\xd9\x85\xd9\x88\xd8\xb7\xd8\xa9" nocase fullword
    $cp1256 = "\xd4\xd1\xe3\xe6\xd8\xc9" nocase fullword
    $wide = "\x34\x06\x31\x06\x45\x06\x48\x06\x37\x06\x29\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_5 {
  meta:
    info = "عاهرة"
  strings:
    $utf8 = "\xd8\xb9\xd8\xa7\xd9\x87\xd8\xb1\xd8\xa9" nocase fullword
    $cp1256 = "\xda\xc7\xe5\xd1\xc9" nocase fullword
    $wide = "\x39\x06\x27\x06\x47\x06\x31\x06\x29\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_6 {
  meta:
    info = "قحبة"
  strings:
    $utf8 = "\xd9\x82\xd8\xad\xd8\xa8\xd8\xa9" nocase fullword
    $cp1256 = "\xde\xcd\xc8\xc9" nocase fullword
    $wide = "\x42\x06\x2d\x06\x28\x06\x29\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_7 {
  meta:
    info = "منيوك"
  strings:
    $utf8 = "\xd9\x85\xd9\x86\xd9\x8a\xd9\x88\xd9\x83" nocase fullword
    $cp1256 = "\xe3\xe4\xed\xe6\xdf" nocase fullword
    $wide = "\x45\x06\x46\x06\x4a\x06\x48\x06\x43\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_8 {
  meta:
    info = "نيك"
  strings:
    $utf8 = "\xd9\x86\xd9\x8a\xd9\x83" nocase fullword
    $cp1256 = "\xe4\xed\xdf" nocase fullword
    $wide = "\x46\x06\x4a\x06\x43\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_9 {
  meta:
    info = "ينيك"
  strings:
    $utf8 = "\xd9\x8a\xd9\x86\xd9\x8a\xd9\x83" nocase fullword
    $cp1256 = "\xed\xe4\xed\xdf" nocase fullword
    $wide = "\x4a\x06\x46\x06\x4a\x06\x43\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_10 {
  meta:
    info = "كسمك"
  strings:
    $utf8 = "\xd9\x83\xd8\xb3\xd9\x85\xd9\x83" nocase fullword
    $cp1256 = "\xdf\xd3\xe3\xdf" nocase fullword
    $wide = "\x43\x06\x33\x06\x45\x06\x43\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_11 {
  meta:
    info = "ابن الشرموطة"
  strings:
    $utf8 = "\xd8\xa7\xd8\xa8\xd9\x86\x20\xd8\xa7\xd9\x84\xd8\xb4\xd8\xb1\xd9\x85\xd9\x88\xd8\xb7\xd8\xa9" nocase fullword
    $cp1256 = "\xc7\xc8\xe4\x20\xc7\xe1\xd4\xd1\xe3\xe6\xd8\xc9" nocase fullword
    $wide = "\x27\x06\x28\x06\x46\x06\x20\x00\x27\x06\x44\x06\x34\x06\x31\x06\x45\x06\x48\x06\x37\x06\x29\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_12 {
  meta:
    info = "ابن القحبة"
  strings:
    $utf8 = "\xd8\xa7\xd8\xa8\xd9\x86\x20\xd8\xa7\xd9\x84\xd9\x82\xd8\xad\xd8\xa8\xd8\xa9" nocase fullword
    $cp1256 = "\xc7\xc8\xe4\x20\xc7\xe1\xde\xcd\xc8\xc9" nocase fullword
    $wide = "\x27\x06\x28\x06\x46\x06\x20\x00\x27\x06\x44\x06\x42\x06\x2d\x06\x28\x06\x29\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_13 {
  meta:
    info = "خول"
  strings:
    $utf8 = "\xd8\xae\xd9\x88\xd9\x84" nocase fullword
    $cp1256 = "\xce\xe6\xe1" nocase fullword
    $wide = "\x2e\x06\x48\x06\x44\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_16 {
  meta:
    info = "متناك"
  strings:
    $utf8 = "\xd9\x85\xd8\xaa\xd9\x86\xd8\xa7\xd9\x83" nocase fullword
    $cp1256 = "\xe3\xca\xe4\xc7\xdf" nocase fullword
    $wide = "\x45\x06\x2a\x06\x46\x06\x27\x06\x43\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_22 {
  meta:
    info = "خرا"
  strings:
    $utf8 = "\xd8\xae\xd8\xb1\xd8\xa7" nocase fullword
    $cp1256 = "\xce\xd1\xc7" nocase fullword
    $wide = "\x2e\x06\x31\x06\x27\x06" nocase fullword
  condition:
    any of them
}

rule content_ar_language_nsfw_25 {
  meta:
    info = "ديوث"
  strings:
    $utf8 = "\xd8\xaf\xd9\x8a\xd9\x88\xd8\xab" nocase fullword
    $cp1256 = "\xcf\xed\xe6\xcb" nocase fullword
    $wide = "\x2f\x06\x4a\x06\x48\x06\x2b\x06" nocase fullword
  condition:
    any of them
}


rule content_ar_language_nsfw_test {
  meta:
    info = "Test rule for ar language detection - UUID: DC50B92E-2C51-4083-A848-D13897C837A9"
  strings:
    $ = "DC50B92E-2C51-4083-A848-D13897C837A9" fullword wide ascii nocase
  condition:
    any of them
}
