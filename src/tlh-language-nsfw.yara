
rule content_tlh_language_nsfw_1 {
  strings:
    $ = "QI'yaH" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_tlh_language_nsfw_2 {
  strings:
    $ = "Qu'vatlh" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_tlh_language_nsfw_3 {
  strings:
    $ = "ghuy'cha'" ascii wide nocase fullword
  condition:
    1 of them
}
