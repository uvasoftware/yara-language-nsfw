rule content_no_language_nsfw {
  strings:
      $  =  "drittsekk"  fullword wide ascii nocase
      $  =  "faen i helvete"  fullword wide ascii nocase
      $  =  "fitte"  fullword wide ascii nocase
      $  =  "jævla"  fullword wide ascii nocase
      $  =  "kuk"  fullword wide ascii nocase
      $  =  "kukene"  fullword wide ascii nocase
      $  =  "kuker"  fullword wide ascii nocase
      $  =  "nigger"  fullword wide ascii nocase
      $  =  "pikk"  fullword wide ascii nocase
      $  =  "sotrør"  fullword wide ascii nocase
      $  =  "ståpikk"  fullword wide ascii nocase
      $  =  "ståpikkene"  fullword wide ascii nocase
      $  =  "ståpikker"  fullword wide ascii nocase
  condition:
    1 of them
}
