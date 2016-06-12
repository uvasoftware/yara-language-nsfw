rule content_pl_language_nsfw {
  strings:
      $  =  "burdel"  fullword wide ascii nocase
      $  =  "burdelmama"  fullword wide ascii nocase
      $  =  "chuj"  fullword wide ascii nocase
      $  =  "chujnia"  fullword wide ascii nocase
      $  =  "ciota"  fullword wide ascii nocase
      $  =  "cipa"  fullword wide ascii nocase
      $  =  "cyc"  fullword wide ascii nocase
      $  =  "debil"  fullword wide ascii nocase
      $  =  "dmuchać"  fullword wide ascii nocase
      $  =  "do kurwy nędzy"  fullword wide ascii nocase
      $  =  "dupa"  fullword wide ascii nocase
      $  =  "dupek"  fullword wide ascii nocase
      $  =  "duperele"  fullword wide ascii nocase
      $  =  "dziwka"  fullword wide ascii nocase
      $  =  "fiut"  fullword wide ascii nocase
      $  =  "gówno"  fullword wide ascii nocase
      $  =  "gówno prawda"  fullword wide ascii nocase
      $  =  "huj"  fullword wide ascii nocase
      $  =  "ja pierdolę"  fullword wide ascii nocase
      $  =  "jajco"  fullword wide ascii nocase
      $  =  "jajeczko"  fullword wide ascii nocase
      $  =  "jajko"  fullword wide ascii nocase
      $  =  "jajo"  fullword wide ascii nocase
      $  =  "jebany"  fullword wide ascii nocase
      $  =  "jebać"  fullword wide ascii nocase
      $  =  "kurwa"  fullword wide ascii nocase
      $  =  "kurwy"  fullword wide ascii nocase
      $  =  "kutafon"  fullword wide ascii nocase
      $  =  "kutas"  fullword wide ascii nocase
      $  =  "lizać pałę"  fullword wide ascii nocase
      $  =  "obciągać chuja"  fullword wide ascii nocase
      $  =  "obciągać fiuta"  fullword wide ascii nocase
      $  =  "obciągać loda"  fullword wide ascii nocase
      $  =  "pieprzyć"  fullword wide ascii nocase
      $  =  "pierdolec"  fullword wide ascii nocase
      $  =  "pierdolić"  fullword wide ascii nocase
      $  =  "pierdolnięty"  fullword wide ascii nocase
      $  =  "pierdoła"  fullword wide ascii nocase
      $  =  "pierdzieć"  fullword wide ascii nocase
      $  =  "pizda"  fullword wide ascii nocase
      $  =  "pojeb"  fullword wide ascii nocase
      $  =  "popierdolony"  fullword wide ascii nocase
      $  =  "robic loda"  fullword wide ascii nocase
      $  =  "robić loda"  fullword wide ascii nocase
      $  =  "ruchać"  fullword wide ascii nocase
      $  =  "rzygać"  fullword wide ascii nocase
      $  =  "skurwysyn"  fullword wide ascii nocase
      $  =  "sraczka"  fullword wide ascii nocase
      $  =  "srać"  fullword wide ascii nocase
      $  =  "suka"  fullword wide ascii nocase
      $  =  "syf"  fullword wide ascii nocase
      $  =  "wkurwiać"  fullword wide ascii nocase
      $  =  "zajebisty"  fullword wide ascii nocase
  condition:
    1 of them
}
