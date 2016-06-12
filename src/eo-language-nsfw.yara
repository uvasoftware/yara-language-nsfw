rule content_eo_language_nsfw {
  strings:
    $  =  "bugren"  fullword wide ascii nocase
    $  =  "bugri"  fullword wide ascii nocase
    $  =  "bugru"  fullword wide ascii nocase
    $  =  "diofek"  fullword wide ascii nocase
    $  =  "diofeka"  fullword wide ascii nocase
    $  =  "fek"  fullword wide ascii nocase
    $  =  "feken"  fullword wide ascii nocase
    $  =  "fekfikanto"  fullword wide ascii nocase
    $  =  "feklekulo"  fullword wide ascii nocase
    $  =  "fekulo"  fullword wide ascii nocase
    $  =  "fik"  fullword wide ascii nocase
    $  =  "fikado"  fullword wide ascii nocase
    $  =  "fikema"  fullword wide ascii nocase
    $  =  "fikfek"  fullword wide ascii nocase
    $  =  "fiki"  fullword wide ascii nocase
    $  =  "fikilo"  fullword wide ascii nocase
    $  =  "fikiĝi"  fullword wide ascii nocase
    $  =  "fikiĝu"  fullword wide ascii nocase
    $  =  "fikklaŭno"  fullword wide ascii nocase
    $  =  "fikota"  fullword wide ascii nocase
    $  =  "fiku"  fullword wide ascii nocase
    $  =  "forfiki"  fullword wide ascii nocase
    $  =  "forfikiĝu"  fullword wide ascii nocase
    $  =  "forfiku"  fullword wide ascii nocase
    $  =  "forfurzu"  fullword wide ascii nocase
    $  =  "forpisi"  fullword wide ascii nocase
    $  =  "forpisu"  fullword wide ascii nocase
    $  =  "furzulo"  fullword wide ascii nocase
    $  =  "kacen"  fullword wide ascii nocase
    $  =  "kaco"  fullword wide ascii nocase
    $  =  "kacsuĉulo"  fullword wide ascii nocase
    $  =  "kojono"  fullword wide ascii nocase
    $  =  "piĉen"  fullword wide ascii nocase
    $  =  "piĉo"  fullword wide ascii nocase
    $  =  "zamenfek"  fullword wide ascii nocase
    $  =  "ĉiesulino"  fullword wide ascii nocase
    $  =  "ĉiesulo"  fullword wide ascii nocase
  condition:
    1 of them
}
