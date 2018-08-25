rule content_en_language_nsfw_racial_1 {
  strings:
    $ =  "kike"  fullword wide ascii nocase
    $ =  "kikes"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_racial_2 {
  strings:
    $ =  "beaner"  fullword wide ascii nocase
    $ =  "beaners"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_racial_3 {
  strings:
    $ =  "nig nog"  fullword wide ascii nocase
    $ =  "nig nogs"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_racial_4 {
  strings:
    $ =  "nigga"  fullword wide ascii nocase
    $ =  "niggas"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_racial_5 {
  strings:
    $ =  "nigger"  fullword wide ascii nocase
    $ =  "niggers"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_racial_6 {
  strings:
    $ =  "raghead"  fullword wide ascii nocase
    $ =  "ragheads"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_racial_7 {
  strings:
    $ =  "slanteye"  fullword wide ascii nocase
    $ =  "slanteyes"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_racial_8 {
  strings:
    $ =  "towelhead"  fullword wide ascii nocase
    $ =  "towelheads"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_racial_9 {
  strings:
    $ =  "whity"  fullword wide ascii nocase
    $ =  "whities"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_racial_10 {
  strings:
    $ =  "wetback"  fullword wide ascii nocase
    $ =  "wetbacks"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_racial_11 {
  strings:
    $ =  "spic"  fullword wide ascii nocase
    $ =  "spics"  fullword wide ascii nocase
  condition:
    1 of them
}
