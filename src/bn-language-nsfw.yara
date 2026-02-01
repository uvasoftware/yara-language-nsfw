rule content_bn_language_nsfw_1 {
  meta:
    info = "চোদা"
  strings:
    $utf8 = "\xe0\xa6\x9a\xe0\xa7\x8b\xe0\xa6\xa6\xe0\xa6\xbe" nocase fullword
    $wide = "\x9a\x09\xcb\x09\xa6\x09\xbe\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_2 {
  meta:
    info = "মাগি"
  strings:
    $utf8 = "\xe0\xa6\xae\xe0\xa6\xbe\xe0\xa6\x97\xe0\xa6\xbf" nocase fullword
    $wide = "\xae\x09\xbe\x09\x97\x09\xbf\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_3 {
  meta:
    info = "বোকাচোদা"
  strings:
    $utf8 = "\xe0\xa6\xac\xe0\xa7\x8b\xe0\xa6\x95\xe0\xa6\xbe\xe0\xa6\x9a\xe0\xa7\x8b\xe0\xa6\xa6\xe0\xa6\xbe" nocase fullword
    $wide = "\xac\x09\xcb\x09\x95\x09\xbe\x09\x9a\x09\xcb\x09\xa6\x09\xbe\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_4 {
  meta:
    info = "মাদারচোদ"
  strings:
    $utf8 = "\xe0\xa6\xae\xe0\xa6\xbe\xe0\xa6\xa6\xe0\xa6\xbe\xe0\xa6\xb0\xe0\xa6\x9a\xe0\xa7\x8b\xe0\xa6\xa6" nocase fullword
    $wide = "\xae\x09\xbe\x09\xa6\x09\xbe\x09\xb0\x09\x9a\x09\xcb\x09\xa6\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_5 {
  meta:
    info = "বাল"
  strings:
    $utf8 = "\xe0\xa6\xac\xe0\xa6\xbe\xe0\xa6\xb2" nocase fullword
    $wide = "\xac\x09\xbe\x09\xb2\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_6 {
  meta:
    info = "ভোদা"
  strings:
    $utf8 = "\xe0\xa6\xad\xe0\xa7\x8b\xe0\xa6\xa6\xe0\xa6\xbe" nocase fullword
    $wide = "\xad\x09\xcb\x09\xa6\x09\xbe\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_7 {
  meta:
    info = "গুদ"
  strings:
    $utf8 = "\xe0\xa6\x97\xe0\xa7\x81\xe0\xa6\xa6" nocase fullword
    $wide = "\x97\x09\xc1\x09\xa6\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_8 {
  meta:
    info = "লুল"
  strings:
    $utf8 = "\xe0\xa6\xb2\xe0\xa7\x81\xe0\xa6\xb2" nocase fullword
    $wide = "\xb2\x09\xc1\x09\xb2\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_9 {
  meta:
    info = "ধোন"
  strings:
    $utf8 = "\xe0\xa6\xa7\xe0\xa7\x8b\xe0\xa6\xa8" nocase fullword
    $wide = "\xa7\x09\xcb\x09\xa8\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_10 {
  meta:
    info = "পোঁদ"
  strings:
    $utf8 = "\xe0\xa6\xaa\xe0\xa7\x8b\xe0\xa6\x81\xe0\xa6\xa6" nocase fullword
    $wide = "\xaa\x09\xcb\x09\x81\x09\xa6\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_11 {
  meta:
    info = "খানকি"
  strings:
    $utf8 = "\xe0\xa6\x96\xe0\xa6\xbe\xe0\xa6\xa8\xe0\xa6\x95\xe0\xa6\xbf" nocase fullword
    $wide = "\x96\x09\xbe\x09\xa8\x09\x95\x09\xbf\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_12 {
  meta:
    info = "বেশ্যা"
  strings:
    $utf8 = "\xe0\xa6\xac\xe0\xa7\x87\xe0\xa6\xb6\xe0\xa7\x8d\xe0\xa6\xaf\xe0\xa6\xbe" nocase fullword
    $wide = "\xac\x09\xc7\x09\xb6\x09\xcd\x09\xaf\x09\xbe\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_13 {
  meta:
    info = "চুদা"
  strings:
    $utf8 = "\xe0\xa6\x9a\xe0\xa7\x81\xe0\xa6\xa6\xe0\xa6\xbe" nocase fullword
    $wide = "\x9a\x09\xc1\x09\xa6\x09\xbe\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_14 {
  meta:
    info = "চুদি"
  strings:
    $utf8 = "\xe0\xa6\x9a\xe0\xa7\x81\xe0\xa6\xa6\xe0\xa6\xbf" nocase fullword
    $wide = "\x9a\x09\xc1\x09\xa6\x09\xbf\x09" nocase fullword
  condition:
    any of them
}
rule content_bn_language_nsfw_15 {
  meta:
    info = "ছিনাল"
  strings:
    $utf8 = "\xe0\xa6\x9b\xe0\xa6\xbf\xe0\xa6\xa8\xe0\xa6\xbe\xe0\xa6\xb2" nocase fullword
    $wide = "\x9b\x09\xbf\x09\xa8\x09\xbe\x09\xb2\x09" nocase fullword
  condition:
    any of them
}
