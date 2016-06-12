rule content_cs_language_nsfw {
  strings:
  $  =  "bordel"  fullword wide ascii nocase
  $  =  "buzna"  fullword wide ascii nocase
  $  =  "chcanky"  fullword wide ascii nocase
  $  =  "chuj"  fullword wide ascii nocase
  $  =  "debil"  fullword wide ascii nocase
  $  =  "do piče"  fullword wide ascii nocase
  $  =  "do prdele"  fullword wide ascii nocase
  $  =  "držka"  fullword wide ascii nocase
  $  =  "dršťka"  fullword wide ascii nocase
  $  =  "flundra"  fullword wide ascii nocase
  $  =  "hajzl"  fullword wide ascii nocase
  $  =  "hovno"  fullword wide ascii nocase
  $  =  "jebat"  fullword wide ascii nocase
  $  =  "kokot"  fullword wide ascii nocase
  $  =  "kokotina"  fullword wide ascii nocase
  $  =  "koňomrd"  fullword wide ascii nocase
  $  =  "kunda"  fullword wide ascii nocase
  $  =  "kurva"  fullword wide ascii nocase
  $  =  "mamrd"  fullword wide ascii nocase
  $  =  "mrdat"  fullword wide ascii nocase
  $  =  "mrdka"  fullword wide ascii nocase
  $  =  "mrdník"  fullword wide ascii nocase
  $  =  "oslošoust"  fullword wide ascii nocase
  $  =  "pizda"  fullword wide ascii nocase
  $  =  "piča"  fullword wide ascii nocase
  $  =  "prcat"  fullword wide ascii nocase
  $  =  "prdel"  fullword wide ascii nocase
  $  =  "prdelka"  fullword wide ascii nocase
  $  =  "píchat"  fullword wide ascii nocase
  $  =  "píčus"  fullword wide ascii nocase
  $  =  "sračka"  fullword wide ascii nocase
  $  =  "srát"  fullword wide ascii nocase
  $  =  "vypíčenec"  fullword wide ascii nocase
  $  =  "zkurvit"  fullword wide ascii nocase
  $  =  "zkurvysyn"  fullword wide ascii nocase
  $  =  "zmrd"  fullword wide ascii nocase
  $  =  "šoustat"  fullword wide ascii nocase
  $  =  "žrát"  fullword wide ascii nocase
  $  =  "šulin"  fullword wide ascii nocase
  $  =  "čumět"  fullword wide ascii nocase
  $  =  "čurák"  fullword wide ascii nocase
condition:
  1 of them
}
