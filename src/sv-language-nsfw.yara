rule content_sv_language_nsfw {
  strings:
      $  =  "arsle"  fullword wide ascii nocase
      $  =  "brutta"  fullword wide ascii nocase
      $  =  "discofitta"  fullword wide ascii nocase
      $  =  "dra åt helvete"  fullword wide ascii nocase
      $  =  "fan"  fullword wide ascii nocase
      $  =  "fitta"  fullword wide ascii nocase
      $  =  "fittig"  fullword wide ascii nocase
      $  =  "för helvete"  fullword wide ascii nocase
      $  =  "helvete"  fullword wide ascii nocase
      $  =  "hård"  fullword wide ascii nocase
      $  =  "jävlar"  fullword wide ascii nocase
      $  =  "knulla"  fullword wide ascii nocase
      $  =  "kuk"  fullword wide ascii nocase
      $  =  "kuksås"  fullword wide ascii nocase
      $  =  "kötthuvud"  fullword wide ascii nocase
      $  =  "köttnacke"  fullword wide ascii nocase
      $  =  "moona"  fullword wide ascii nocase
      $  =  "moonade"  fullword wide ascii nocase
      $  =  "moonar"  fullword wide ascii nocase
      $  =  "moonat"  fullword wide ascii nocase
      $  =  "mutta"  fullword wide ascii nocase
      $  =  "neger"  fullword wide ascii nocase
      $  =  "nigger"  fullword wide ascii nocase
      $  =  "olla"  fullword wide ascii nocase
      $  =  "pippa"  fullword wide ascii nocase
      $  =  "pitt"  fullword wide ascii nocase
      $  =  "prutt"  fullword wide ascii nocase
      $  =  "pök"  fullword wide ascii nocase
      $  =  "runka"  fullword wide ascii nocase
      $  =  "röv"  fullword wide ascii nocase
      $  =  "rövhål"  fullword wide ascii nocase
      $  =  "rövknulla"  fullword wide ascii nocase
      $  =  "satan"  fullword wide ascii nocase
      $  =  "skit ner dig"  fullword wide ascii nocase
      $  =  "skita"  fullword wide ascii nocase
      $  =  "skäggbiff"  fullword wide ascii nocase
      $  =  "snedfitta"  fullword wide ascii nocase
      $  =  "snefitta"  fullword wide ascii nocase
      $  =  "stake"  fullword wide ascii nocase
      $  =  "subba"  fullword wide ascii nocase
      $  =  "sätta på"  fullword wide ascii nocase
      $  =  "sås"  fullword wide ascii nocase
      $  =  "tusan"  fullword wide ascii nocase
  condition:
    1 of them
}
