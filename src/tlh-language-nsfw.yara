rule content_tlh_language_nsfw {
  strings:
      $  =  "QI'yaH"  fullword wide ascii nocase
      $  =  "Qu'vatlh"  fullword wide ascii nocase
      $  =  "ghuy'cha'"  fullword wide ascii nocase
  condition:
    1 of them
}
