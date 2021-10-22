
rule content_da_language_nsfw_1 {
  strings:
    $ = "anus" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_2 {
  strings:
    $ = "bøsserøv" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_3 {
  strings:
    $ = "cock" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_4 {
  strings:
    $ = "fisse" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_5 {
  strings:
    $ = "fissehår" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_6 {
  strings:
    $ = "fuck" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_7 {
  strings:
    $ = "hestepik" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_8 {
  strings:
    $ = "kussekryller" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_9 {
  strings:
    $ = "lort" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_10 {
  strings:
    $ = "luder" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_11 {
  strings:
    $ = "pik" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_12 {
  strings:
    $ = "pikhår" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_13 {
  strings:
    $ = "pikslugeri" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_14 {
  strings:
    $ = "piksutteri" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_15 {
  strings:
    $ = "pis" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_16 {
  strings:
    $ = "røv" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_17 {
  strings:
    $ = "røvhul" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_18 {
  strings:
    $ = "røvskæg" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_19 {
  strings:
    $ = "røvspræke" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_da_language_nsfw_20 {
  strings:
    $ = "shit" ascii wide nocase fullword
  condition:
    1 of them
}
