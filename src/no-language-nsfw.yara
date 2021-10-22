
rule content_no_language_nsfw_1 {
  strings:
    $ = "drittsekk" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_no_language_nsfw_2 {
  strings:
    $ = "faen i helvete" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_no_language_nsfw_3 {
  strings:
    $ = "fitte" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_no_language_nsfw_4 {
  strings:
    $ = "jævla" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_no_language_nsfw_5 {
  strings:
    $ = "kuk" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_no_language_nsfw_6 {
  strings:
    $ = "kukene" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_no_language_nsfw_7 {
  strings:
    $ = "kuker" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_no_language_nsfw_8 {
  strings:
    $ = "nigger" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_no_language_nsfw_9 {
  strings:
    $ = "pikk" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_no_language_nsfw_10 {
  strings:
    $ = "sotrør" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_no_language_nsfw_11 {
  strings:
    $ = "ståpikk" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_no_language_nsfw_12 {
  strings:
    $ = "ståpikkene" ascii wide nocase fullword
  condition:
    1 of them
}

rule content_no_language_nsfw_13 {
  strings:
    $ = "ståpikker" ascii wide nocase fullword
  condition:
    1 of them
}
