rule content_da_language_nsfw {
  strings:
    $  =  "anus"  fullword wide ascii nocase
    $  =  "bøsserøv"  fullword wide ascii nocase
    $  =  "cock"  fullword wide ascii nocase
    $  =  "fisse"  fullword wide ascii nocase
    $  =  "fissehår"  fullword wide ascii nocase
    $  =  "fuck"  fullword wide ascii nocase
    $  =  "hestepik"  fullword wide ascii nocase
    $  =  "kussekryller"  fullword wide ascii nocase
    $  =  "lort"  fullword wide ascii nocase
    $  =  "luder"  fullword wide ascii nocase
    $  =  "pik"  fullword wide ascii nocase
    $  =  "pikhår"  fullword wide ascii nocase
    $  =  "pikslugeri"  fullword wide ascii nocase
    $  =  "piksutteri"  fullword wide ascii nocase
    $  =  "pis"  fullword wide ascii nocase
    $  =  "røv"  fullword wide ascii nocase
    $  =  "røvhul"  fullword wide ascii nocase
    $  =  "røvskæg"  fullword wide ascii nocase
    $  =  "røvspræke"  fullword wide ascii nocase
    $  =  "shit"  fullword wide ascii nocase
  condition:
    1 of them
}
