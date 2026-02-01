rule content_en_language_nsfw_3 {
  meta:
    info = "arsehole"
  strings:
    $ascii1 = "\x61\x72\x73\x65\x68\x6f\x6c\x65" nocase fullword  // arsehole in ASCII/UTF-8
    $wide1 = "\x61\x00\x72\x00\x73\x00\x65\x00\x68\x00\x6f\x00\x6c\x00\x65\x00" nocase fullword  // arsehole in UTF-16LE
    $ascii2 = "\x61\x73\x73\x68\x6f\x6c\x65" nocase fullword  // asshole in ASCII/UTF-8
    $wide2 = "\x61\x00\x73\x00\x73\x00\x68\x00\x6f\x00\x6c\x00\x65\x00" nocase fullword  // asshole in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_4 {
  meta:
    info = "assmunch"
  strings:
    $ascii = "\x61\x73\x73\x6d\x75\x6e\x63\x68" nocase fullword  // assmunch in ASCII/UTF-8
    $wide = "\x61\x00\x73\x00\x73\x00\x6d\x00\x75\x00\x6e\x00\x63\x00\x68\x00" nocase fullword  // assmunch in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_18 {
  meta:
    info = "blowjob"
  strings:
    $ascii1 = "\x62\x6c\x6f\x77\x6a\x6f\x62" nocase fullword  // blowjob in ASCII/UTF-8
    $wide1 = "\x62\x00\x6c\x00\x6f\x00\x77\x00\x6a\x00\x6f\x00\x62\x00" nocase fullword  // blowjob in UTF-16LE
    $ascii2 = "\x62\x6c\x6f\x77\x6a\x6f\x62\x73" nocase fullword  // blowjobs in ASCII/UTF-8
    $wide2 = "\x62\x00\x6c\x00\x6f\x00\x77\x00\x6a\x00\x6f\x00\x62\x00\x73\x00" nocase fullword  // blowjobs in UTF-16LE
    $ascii3 = "\x62\x6c\x6f\x77\x20\x6a\x6f\x62" nocase fullword  // blow job in ASCII/UTF-8
    $wide3 = "\x62\x00\x6c\x00\x6f\x00\x77\x00\x20\x00\x6a\x00\x6f\x00\x62\x00" nocase fullword  // blow job in UTF-16LE
    $ascii4 = "\x62\x6c\x6f\x77\x20\x6a\x6f\x62\x73" nocase fullword  // blow jobs in ASCII/UTF-8
    $wide4 = "\x62\x00\x6c\x00\x6f\x00\x77\x00\x20\x00\x6a\x00\x6f\x00\x62\x00\x73\x00" nocase fullword  // blow jobs in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_25 {
  meta:
    info = "bukkake"
  strings:
    $ascii = "\x62\x75\x6b\x6b\x61\x6b\x65" nocase fullword  // bukkake in ASCII/UTF-8
    $wide = "\x62\x00\x75\x00\x6b\x00\x6b\x00\x61\x00\x6b\x00\x65\x00" nocase fullword  // bukkake in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_26 {
  meta:
    info = "bulldyke"
  strings:
    $ascii = "\x62\x75\x6c\x6c\x64\x79\x6b\x65" nocase fullword  // bulldyke in ASCII/UTF-8
    $wide = "\x62\x00\x75\x00\x6c\x00\x6c\x00\x64\x00\x79\x00\x6b\x00\x65\x00" nocase fullword  // bulldyke in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_27 {
  meta:
    info = "bullshit"
  strings:
    $ascii1 = "\x62\x75\x6c\x6c\x73\x68\x69\x74" nocase fullword  // bullshit in ASCII/UTF-8
    $wide1 = "\x62\x00\x75\x00\x6c\x00\x6c\x00\x73\x00\x68\x00\x69\x00\x74\x00" nocase fullword  // bullshit in UTF-16LE
    $ascii2 = "\x62\x75\x6c\x6c\x20\x73\x68\x69\x74" nocase fullword  // bull shit in ASCII/UTF-8
    $wide2 = "\x62\x00\x75\x00\x6c\x00\x6c\x00\x20\x00\x73\x00\x68\x00\x69\x00\x74\x00" nocase fullword  // bull shit in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_34 {
  meta:
    info = "camgirl"
  strings:
    $ascii = "\x63\x61\x6d\x67\x69\x72\x6c" nocase fullword  // camgirl in ASCII/UTF-8
    $wide = "\x63\x00\x61\x00\x6d\x00\x67\x00\x69\x00\x72\x00\x6c\x00" nocase fullword  // camgirl in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_35 {
  meta:
    info = "camslut"
  strings:
    $ascii = "\x63\x61\x6d\x73\x6c\x75\x74" nocase fullword  // camslut in ASCII/UTF-8
    $wide = "\x63\x00\x61\x00\x6d\x00\x73\x00\x6c\x00\x75\x00\x74\x00" nocase fullword  // camslut in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_36 {
  meta:
    info = "camwhore"
  strings:
    $ascii = "\x63\x61\x6d\x77\x68\x6f\x72\x65" nocase fullword  // camwhore in ASCII/UTF-8
    $wide = "\x63\x00\x61\x00\x6d\x00\x77\x00\x68\x00\x6f\x00\x72\x00\x65\x00" nocase fullword  // camwhore in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_41 {
  meta:
    info = "clusterfuck"
  strings:
    $ascii = "\x63\x6c\x75\x73\x74\x65\x72\x66\x75\x63\x6b" nocase fullword  // clusterfuck in ASCII/UTF-8
    $wide = "\x63\x00\x6c\x00\x75\x00\x73\x00\x74\x00\x65\x00\x72\x00\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // clusterfuck in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_44 {
  meta:
    info = "coprolagnia"
  strings:
    $ascii1 = "\x63\x6f\x70\x72\x6f\x6c\x61\x67\x6e\x69\x61" nocase fullword  // coprolagnia in ASCII/UTF-8
    $wide1 = "\x63\x00\x6f\x00\x70\x00\x72\x00\x6f\x00\x6c\x00\x61\x00\x67\x00\x6e\x00\x69\x00\x61\x00" nocase fullword  // coprolagnia in UTF-16LE
    $ascii2 = "\x63\x6f\x70\x72\x6f\x70\x68\x69\x6c\x69\x61" nocase fullword  // coprophilia in ASCII/UTF-8
    $wide2 = "\x63\x00\x6f\x00\x70\x00\x72\x00\x6f\x00\x70\x00\x68\x00\x69\x00\x6c\x00\x69\x00\x61\x00" nocase fullword  // coprophilia in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_45 {
  meta:
    info = "creampie"
  strings:
    $ascii = "\x63\x72\x65\x61\x6d\x70\x69\x65" nocase fullword  // creampie in ASCII/UTF-8
    $wide = "\x63\x00\x72\x00\x65\x00\x61\x00\x6d\x00\x70\x00\x69\x00\x65\x00" nocase fullword  // creampie in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_49 {
  meta:
    info = "cunt"
  strings:
    $ascii = "\x63\x75\x6e\x74" nocase fullword  // cunt in ASCII/UTF-8
    $wide = "\x63\x00\x75\x00\x6e\x00\x74\x00" nocase fullword  // cunt in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_52 {
  meta:
    info = "dingleberries"
  strings:
    $ascii1 = "\x64\x69\x6e\x67\x6c\x65\x62\x65\x72\x72\x69\x65\x73" nocase fullword  // dingleberries in ASCII/UTF-8
    $wide1 = "\x64\x00\x69\x00\x6e\x00\x67\x00\x6c\x00\x65\x00\x62\x00\x65\x00\x72\x00\x72\x00\x69\x00\x65\x00\x73\x00" nocase fullword  // dingleberries in UTF-16LE
    $ascii2 = "\x64\x69\x6e\x67\x6c\x65\x62\x65\x72\x72\x79" nocase fullword  // dingleberry in ASCII/UTF-8
    $wide2 = "\x64\x00\x69\x00\x6e\x00\x67\x00\x6c\x00\x65\x00\x62\x00\x65\x00\x72\x00\x72\x00\x79\x00" nocase fullword  // dingleberry in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_59 {
  meta:
    info = "figging"
  strings:
    $ascii = "\x66\x69\x67\x67\x69\x6e\x67" nocase fullword  // figging in ASCII/UTF-8
    $wide = "\x66\x00\x69\x00\x67\x00\x67\x00\x69\x00\x6e\x00\x67\x00" nocase fullword  // figging in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_60 {
  meta:
    info = "fingerbang"
  strings:
    $ascii = "\x66\x69\x6e\x67\x65\x72\x62\x61\x6e\x67" nocase fullword  // fingerbang in ASCII/UTF-8
    $wide = "\x66\x00\x69\x00\x6e\x00\x67\x00\x65\x00\x72\x00\x62\x00\x61\x00\x6e\x00\x67\x00" nocase fullword  // fingerbang in UTF-16LE
  condition:
    any of them
}  
 
rule content_en_language_nsfw_62 {
  meta:
    info = "fisting"
  strings:
    $ascii = "\x66\x69\x73\x74\x69\x6e\x67" nocase fullword  // fisting in ASCII/UTF-8
    $wide = "\x66\x00\x69\x00\x73\x00\x74\x00\x69\x00\x6e\x00\x67\x00" nocase fullword  // fisting in UTF-16LE
  condition:
    any of them
} 
rule content_en_language_nsfw_63 {
  meta:
    info = "footjob"
  strings:
    $ascii = "\x66\x6f\x6f\x74\x6a\x6f\x62" nocase fullword  // footjob in ASCII/UTF-8
    $wide = "\x66\x00\x6f\x00\x6f\x00\x74\x00\x6a\x00\x6f\x00\x62\x00" nocase fullword  // footjob in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_64 {
  meta:
    info = "frotting"
  strings:
    $ascii = "\x66\x72\x6f\x74\x74\x69\x6e\x67" nocase fullword  // frotting in ASCII/UTF-8
    $wide = "\x66\x00\x72\x00\x6f\x00\x74\x00\x74\x00\x69\x00\x6e\x00\x67\x00" nocase fullword  // frotting in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_65 {
  meta:
    info = "fuck"
  strings:
    $ascii1 = "\x66\x75\x63\x6b" nocase fullword  // fuck in ASCII/UTF-8
    $wide1 = "\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // fuck in UTF-16LE
    $ascii2 = "\x66\x75\x63\x6b\x73" nocase fullword  // fucks in ASCII/UTF-8
    $wide2 = "\x66\x00\x75\x00\x63\x00\x6b\x00\x73\x00" nocase fullword  // fucks in UTF-16LE
    $ascii3 = "\x66\x2a\x2a\x2a" nocase fullword  // f*** in ASCII/UTF-8
    $wide3 = "\x66\x00\x2a\x00\x2a\x00\x2a\x00" nocase fullword  // f*** in UTF-16LE
    $ascii4 = "\x66\x2a\x2a\x2a\x2a" nocase fullword  // f**** in ASCII/UTF-8
    $wide4 = "\x66\x00\x2a\x00\x2a\x00\x2a\x00\x2a\x00" nocase fullword  // f**** in UTF-16LE
    $ascii5 = "\x66\x75\x63\x6b\x65\x64" nocase fullword  // fucked in ASCII/UTF-8
    $wide5 = "\x66\x00\x75\x00\x63\x00\x6b\x00\x65\x00\x64\x00" nocase fullword  // fucked in UTF-16LE
    $ascii6 = "\x66\x75\x63\x6b\x69\x6e\x67" nocase fullword  // fucking in ASCII/UTF-8
    $wide6 = "\x66\x00\x75\x00\x63\x00\x6b\x00\x69\x00\x6e\x00\x67\x00" nocase fullword  // fucking in UTF-16LE
    $ascii7 = "\x66\x75\x63\x6b\x69\x6e" nocase fullword  // fuckin in ASCII/UTF-8
    $wide7 = "\x66\x00\x75\x00\x63\x00\x6b\x00\x69\x00\x6e\x00" nocase fullword  // fuckin in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_67 {
  meta:
    info = "fucktard"
  strings:
    $ascii1 = "\x66\x75\x63\x6b\x74\x61\x72\x64" nocase fullword  // fucktard in ASCII/UTF-8
    $wide1 = "\x66\x00\x75\x00\x63\x00\x6b\x00\x74\x00\x61\x00\x72\x00\x64\x00" nocase fullword  // fucktard in UTF-16LE
    $ascii2 = "\x66\x75\x63\x6b\x74\x61\x72\x64\x73" nocase fullword  // fucktards in ASCII/UTF-8
    $wide2 = "\x66\x00\x75\x00\x63\x00\x6b\x00\x74\x00\x61\x00\x72\x00\x64\x00\x73\x00" nocase fullword  // fucktards in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_68 {
  meta:
    info = "fudge packer"
  strings:
    $ascii1 = "\x66\x75\x64\x67\x65\x20\x70\x61\x63\x6b\x65\x72" nocase fullword  // fudge packer in ASCII/UTF-8
    $wide1 = "\x66\x00\x75\x00\x64\x00\x67\x00\x65\x00\x20\x00\x70\x00\x61\x00\x63\x00\x6b\x00\x65\x00\x72\x00" nocase fullword  // fudge packer in UTF-16LE
    $ascii2 = "\x66\x75\x64\x67\x65\x70\x61\x63\x6b\x65\x72" nocase fullword  // fudgepacker in ASCII/UTF-8
    $wide2 = "\x66\x00\x75\x00\x64\x00\x67\x00\x65\x00\x70\x00\x61\x00\x63\x00\x6b\x00\x65\x00\x72\x00" nocase fullword  // fudgepacker in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_69 {
  meta:
    info = "futanari"
  strings:
    $ascii = "\x66\x75\x74\x61\x6e\x61\x72\x69" nocase fullword  // futanari in ASCII/UTF-8
    $wide = "\x66\x00\x75\x00\x74\x00\x61\x00\x6e\x00\x61\x00\x72\x00\x69\x00" nocase fullword  // futanari in UTF-16LE
  condition:
    any of them
}
  
rule content_en_language_nsfw_71 {
  meta:
    info = "gang bang"
  strings:
    $ascii1 = "\x67\x61\x6e\x67\x20\x62\x61\x6e\x67" nocase fullword  // gang bang in ASCII/UTF-8
    $wide1 = "\x67\x00\x61\x00\x6e\x00\x67\x00\x20\x00\x62\x00\x61\x00\x6e\x00\x67\x00" nocase fullword  // gang bang in UTF-16LE
    $ascii2 = "\x67\x61\x6e\x67\x62\x61\x6e\x67" nocase fullword  // gangbang in ASCII/UTF-8
    $wide2 = "\x67\x00\x61\x00\x6e\x00\x67\x00\x62\x00\x61\x00\x6e\x00\x67\x00" nocase fullword  // gangbang in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_74 {
  meta:
    info = "gokkun"
  strings:
    $ascii = "\x67\x6f\x6b\x6b\x75\x6e" nocase fullword  // gokkun in ASCII/UTF-8
    $wide = "\x67\x00\x6f\x00\x6b\x00\x6b\x00\x75\x00\x6e\x00" nocase fullword  // gokkun in UTF-16LE
  condition:
    any of them
} 
rule content_en_language_nsfw_77 {
  meta:
    info = "hand job"
  strings:
    $ascii1 = "\x68\x61\x6e\x64\x20\x6a\x6f\x62" nocase fullword  // hand job in ASCII/UTF-8
    $wide1 = "\x68\x00\x61\x00\x6e\x00\x64\x00\x20\x00\x6a\x00\x6f\x00\x62\x00" nocase fullword  // hand job in UTF-16LE
    $ascii2 = "\x68\x61\x6e\x64\x20\x6a\x6f\x62\x73" nocase fullword  // hand jobs in ASCII/UTF-8
    $wide2 = "\x68\x00\x61\x00\x6e\x00\x64\x00\x20\x00\x6a\x00\x6f\x00\x62\x00\x73\x00" nocase fullword  // hand jobs in UTF-16LE
    $ascii3 = "\x68\x61\x6e\x64\x6a\x6f\x62" nocase fullword  // handjob in ASCII/UTF-8
    $wide3 = "\x68\x00\x61\x00\x6e\x00\x64\x00\x6a\x00\x6f\x00\x62\x00" nocase fullword  // handjob in UTF-16LE
    $ascii4 = "\x68\x61\x6e\x64\x6a\x6f\x62\x73" nocase fullword  // handjobs in ASCII/UTF-8
    $wide4 = "\x68\x00\x61\x00\x6e\x00\x64\x00\x6a\x00\x6f\x00\x62\x00\x73\x00" nocase fullword  // handjobs in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_82 {
  meta:
    info = "jack off"
  strings:
    $ascii1 = "\x6a\x61\x63\x6b\x20\x6f\x66\x66" nocase fullword  // jack off in ASCII/UTF-8
    $wide1 = "\x6a\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x6f\x00\x66\x00\x66\x00" nocase fullword  // jack off in UTF-16LE
    $ascii2 = "\x6a\x61\x63\x6b\x6f\x66\x66" nocase fullword  // jackoff in ASCII/UTF-8
    $wide2 = "\x6a\x00\x61\x00\x63\x00\x6b\x00\x6f\x00\x66\x00\x66\x00" nocase fullword  // jackoff in UTF-16LE
    $ascii3 = "\x6a\x61\x63\x6b\x69\x6e\x67\x20\x6f\x66\x66" nocase fullword  // jacking off in ASCII/UTF-8
    $wide3 = "\x6a\x00\x61\x00\x63\x00\x6b\x00\x69\x00\x6e\x00\x67\x00\x20\x00\x6f\x00\x66\x00\x66\x00" nocase fullword  // jacking off in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_84 {
  meta:
    info = "jerk off"
  strings:
    $ascii = "\x6a\x65\x72\x6b\x20\x6f\x66\x66" nocase fullword  // jerk off in ASCII/UTF-8
    $wide = "\x6a\x00\x65\x00\x72\x00\x6b\x00\x20\x00\x6f\x00\x66\x00\x66\x00" nocase fullword  // jerk off in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_86 {
  meta:
    info = "jizz"
  strings:
    $ascii1 = "\x6a\x69\x7a\x7a" nocase fullword  // jizz in ASCII/UTF-8
    $wide1 = "\x6a\x00\x69\x00\x7a\x00\x7a\x00" nocase fullword  // jizz in UTF-16LE
    $ascii2 = "\x6a\x69\x73\x6d" nocase fullword  // jism in ASCII/UTF-8
    $wide2 = "\x6a\x00\x69\x00\x73\x00\x6d\x00" nocase fullword  // jism in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_87 {
  meta:
    info = "kinbaku"
  strings:
    $ascii = "\x6b\x69\x6e\x62\x61\x6b\x75" nocase fullword  // kinbaku in ASCII/UTF-8
    $wide = "\x6b\x00\x69\x00\x6e\x00\x62\x00\x61\x00\x6b\x00\x75\x00" nocase fullword  // kinbaku in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_94 {
  meta:
    info = "motherfucker"
  strings:
    $ascii1 = "\x6d\x6f\x74\x68\x65\x72\x66\x75\x63\x6b\x65\x72" nocase fullword  // motherfucker in ASCII/UTF-8
    $wide1 = "\x6d\x00\x6f\x00\x74\x00\x68\x00\x65\x00\x72\x00\x66\x00\x75\x00\x63\x00\x6b\x00\x65\x00\x72\x00" nocase fullword  // motherfucker in UTF-16LE
    $ascii2 = "\x6d\x6f\x74\x68\x65\x72\x66\x75\x63\x6b\x65\x72\x73" nocase fullword  // motherfuckers in ASCII/UTF-8
    $wide2 = "\x6d\x00\x6f\x00\x74\x00\x68\x00\x65\x00\x72\x00\x66\x00\x75\x00\x63\x00\x6b\x00\x65\x00\x72\x00\x73\x00" nocase fullword  // motherfuckers in UTF-16LE
    $ascii3 = "\x6d\x6f\x74\x68\x65\x72\x20\x66\x75\x63\x6b\x65\x72" nocase fullword  // mother fucker in ASCII/UTF-8
    $wide3 = "\x6d\x00\x6f\x00\x74\x00\x68\x00\x65\x00\x72\x00\x20\x00\x66\x00\x75\x00\x63\x00\x6b\x00\x65\x00\x72\x00" nocase fullword  // mother fucker in UTF-16LE
    $ascii4 = "\x6d\x6f\x74\x68\x65\x72\x20\x66\x75\x63\x6b\x65\x72\x73" nocase fullword  // mother fuckers in ASCII/UTF-8
    $wide4 = "\x6d\x00\x6f\x00\x74\x00\x68\x00\x65\x00\x72\x00\x20\x00\x66\x00\x75\x00\x63\x00\x6b\x00\x65\x00\x72\x00\x73\x00" nocase fullword  // mother fuckers in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_96 {
  meta:
    info = "muff diver"
  strings:
    $ascii = "\x6d\x75\x66\x66\x20\x64\x69\x76\x65\x72" nocase fullword  // muff diver in ASCII/UTF-8
    $wide = "\x6d\x00\x75\x00\x66\x00\x66\x00\x20\x00\x64\x00\x69\x00\x76\x00\x65\x00\x72\x00" nocase fullword  // muff diver in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_97 {
  meta:
    info = "muffdiving"
  strings:
    $ascii = "\x6d\x75\x66\x66\x64\x69\x76\x69\x6e\x67" nocase fullword  // muffdiving in ASCII/UTF-8
    $wide = "\x6d\x00\x75\x00\x66\x00\x66\x00\x64\x00\x69\x00\x76\x00\x69\x00\x6e\x00\x67\x00" nocase fullword  // muffdiving in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_100 {
  meta:
    info = "omorashi"
  strings:
    $ascii = "\x6f\x6d\x6f\x72\x61\x73\x68\x69" nocase fullword  // omorashi in ASCII/UTF-8
    $wide = "\x6f\x00\x6d\x00\x6f\x00\x72\x00\x61\x00\x73\x00\x68\x00\x69\x00" nocase fullword  // omorashi in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_101 {
  meta:
    info = "one cup two girls"
  strings:
    $ascii = "\x6f\x6e\x65\x20\x63\x75\x70\x20\x74\x77\x6f\x20\x67\x69\x72\x6c\x73" nocase fullword  // one cup two girls in ASCII/UTF-8
    $wide = "\x6f\x00\x6e\x00\x65\x00\x20\x00\x63\x00\x75\x00\x70\x00\x20\x00\x74\x00\x77\x00\x6f\x00\x20\x00\x67\x00\x69\x00\x72\x00\x6c\x00\x73\x00" nocase fullword  // one cup two girls in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_103 {
  meta:
    info = "piece of shit"
  strings:
    $ascii1 = "\x70\x69\x65\x63\x65\x20\x6f\x66\x20\x73\x68\x69\x74" nocase fullword  // piece of shit in ASCII/UTF-8
    $wide1 = "\x70\x00\x69\x00\x65\x00\x63\x00\x65\x00\x20\x00\x6f\x00\x66\x00\x20\x00\x73\x00\x68\x00\x69\x00\x74\x00" nocase fullword  // piece of shit in UTF-16LE
    $ascii2 = "\x70\x69\x65\x63\x65\x73\x20\x6f\x66\x20\x73\x68\x69\x74" nocase fullword  // pieces of shit in ASCII/UTF-8
    $wide2 = "\x70\x00\x69\x00\x65\x00\x63\x00\x65\x00\x73\x00\x20\x00\x6f\x00\x66\x00\x20\x00\x73\x00\x68\x00\x69\x00\x74\x00" nocase fullword  // pieces of shit in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_104 {
  meta:
    info = "piss pig"
  strings:
    $ascii = "\x70\x69\x73\x73\x20\x70\x69\x67" nocase fullword  // piss pig in ASCII/UTF-8
    $wide = "\x70\x00\x69\x00\x73\x00\x73\x00\x20\x00\x70\x00\x69\x00\x67\x00" nocase fullword  // piss pig in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_108 {
  meta:
    info = "poontang"
  strings:
    $ascii = "\x70\x6f\x6f\x6e\x74\x61\x6e\x67" nocase fullword  // poontang in ASCII/UTF-8
    $wide = "\x70\x00\x6f\x00\x6f\x00\x6e\x00\x74\x00\x61\x00\x6e\x00\x67\x00" nocase fullword  // poontang in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_109 {
  meta:
    info = "poop chute"
  strings:
    $ascii1 = "\x70\x6f\x6f\x70\x20\x63\x68\x75\x74\x65" nocase fullword  // poop chute in ASCII/UTF-8
    $wide1 = "\x70\x00\x6f\x00\x6f\x00\x70\x00\x20\x00\x63\x00\x68\x00\x75\x00\x74\x00\x65\x00" nocase fullword  // poop chute in UTF-16LE
    $ascii2 = "\x70\x6f\x6f\x70\x63\x68\x75\x74\x65" nocase fullword  // poopchute in ASCII/UTF-8
    $wide2 = "\x70\x00\x6f\x00\x6f\x00\x70\x00\x63\x00\x68\x00\x75\x00\x74\x00\x65\x00" nocase fullword  // poopchute in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_114 {
  meta:
    info = "queaf"
  strings:
    $ascii1 = "\x71\x75\x65\x61\x66" nocase fullword  // queaf in ASCII/UTF-8
    $wide1 = "\x71\x00\x75\x00\x65\x00\x61\x00\x66\x00" nocase fullword  // queaf in UTF-16LE
    $ascii2 = "\x71\x75\x65\x65\x66" nocase fullword  // queef in ASCII/UTF-8
    $wide2 = "\x71\x00\x75\x00\x65\x00\x65\x00\x66\x00" nocase fullword  // queef in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_118 {
  meta:
    info = "rimjob"
  strings:
    $ascii1 = "\x72\x69\x6d\x6a\x6f\x62" nocase fullword  // rimjob in ASCII/UTF-8
    $wide1 = "\x72\x00\x69\x00\x6d\x00\x6a\x00\x6f\x00\x62\x00" nocase fullword  // rimjob in UTF-16LE
    $ascii2 = "\x72\x69\x6d\x6d\x69\x6e\x67" nocase fullword  // rimming in ASCII/UTF-8
    $wide2 = "\x72\x00\x69\x00\x6d\x00\x6d\x00\x69\x00\x6e\x00\x67\x00" nocase fullword  // rimming in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_121 {
  meta:
    info = "schlong"
  strings:
    $ascii1 = "\x73\x63\x68\x6c\x6f\x6e\x67" nocase fullword  // schlong in ASCII/UTF-8
    $wide1 = "\x73\x00\x63\x00\x68\x00\x6c\x00\x6f\x00\x6e\x00\x67\x00" nocase fullword  // schlong in UTF-16LE
    $ascii2 = "\x73\x63\x68\x6c\x6f\x6e\x67\x73" nocase fullword  // schlongs in ASCII/UTF-8
    $wide2 = "\x73\x00\x63\x00\x68\x00\x6c\x00\x6f\x00\x6e\x00\x67\x00\x73\x00" nocase fullword  // schlongs in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_124 {
  meta:
    info = "shibari"
  strings:
    $ascii1 = "\x73\x68\x69\x62\x61\x72\x69" nocase fullword  // shibari in ASCII/UTF-8
    $wide1 = "\x73\x00\x68\x00\x69\x00\x62\x00\x61\x00\x72\x00\x69\x00" nocase fullword  // shibari in UTF-16LE
    $ascii2 = "\x73\x68\x69\x62\x61\x72\x69\x73" nocase fullword  // shibaris in ASCII/UTF-8
    $wide2 = "\x73\x00\x68\x00\x69\x00\x62\x00\x61\x00\x72\x00\x69\x00\x73\x00" nocase fullword  // shibaris in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_130 {
  meta:
    info = "splooge"
  strings:
    $ascii = "\x73\x70\x6c\x6f\x6f\x67\x65" nocase fullword  // splooge in ASCII/UTF-8
    $wide = "\x73\x00\x70\x00\x6c\x00\x6f\x00\x6f\x00\x67\x00\x65\x00" nocase fullword  // splooge in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_131 {
  meta:
    info = "spooge"
  strings:
    $ascii = "\x73\x70\x6f\x6f\x67\x65" nocase fullword  // spooge in ASCII/UTF-8
    $wide = "\x73\x00\x70\x00\x6f\x00\x6f\x00\x67\x00\x65\x00" nocase fullword  // spooge in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_150 {
  meta:
    info = "goregasm"
  strings:
    $ascii1 = "\x67\x6f\x72\x65\x67\x61\x73\x6d" nocase fullword  // goregasm in ASCII/UTF-8
    $wide1 = "\x67\x00\x6f\x00\x72\x00\x65\x00\x67\x00\x61\x00\x73\x00\x6d\x00" nocase fullword  // goregasm in UTF-16LE
    $ascii2 = "\x67\x6f\x72\x65\x67\x61\x73\x6d\x73" nocase fullword  // goregasms in ASCII/UTF-8
    $wide2 = "\x67\x00\x6f\x00\x72\x00\x65\x00\x67\x00\x61\x00\x73\x00\x6d\x00\x73\x00" nocase fullword  // goregasms in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_154 {
  meta:
    info = "F@cking"
  strings:
    $ascii = "\x46\x40\x63\x6b\x69\x6e\x67" nocase fullword  // F@cking in ASCII/UTF-8
    $wide = "\x46\x00\x40\x00\x63\x00\x6b\x00\x69\x00\x6e\x00\x67\x00" nocase fullword  // F@cking in UTF-16LE
  condition:
    any of them
}
rule content_en_language_nsfw_155 {
  meta:
    info = "c0ck"
  strings:
    $ascii = "\x63\x30\x63\x6b" nocase fullword  // c0ck in ASCII/UTF-8
    $wide = "\x63\x00\x30\x00\x63\x00\x6b\x00" nocase fullword  // c0ck in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_156 {
  meta:
    info = "pu$$y"
  strings:
    $ascii = "\x70\x75\x24\x24\x79" nocase fullword  // pu$$y in ASCII/UTF-8
    $wide = "\x70\x00\x75\x00\x24\x00\x24\x00\x79\x00" nocase fullword  // pu$$y in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_157 {
  meta:
    info = "$luts"
  strings:
    $ascii = "\x24\x6c\x75\x74\x73" nocase fullword  // $luts in ASCII/UTF-8
    $wide = "\x24\x00\x6c\x00\x75\x00\x74\x00\x73\x00" nocase fullword  // $luts in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_158 {
  meta:
    info = "h00kers"
  strings:
    $ascii = "\x68\x30\x30\x6b\x65\x72\x73" nocase fullword  // h00kers in ASCII/UTF-8
    $wide = "\x68\x00\x30\x00\x30\x00\x6b\x00\x65\x00\x72\x00\x73\x00" nocase fullword  // h00kers in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_159 {
  meta:
    info = "cre@mpied"
  strings:
    $ascii = "\x63\x72\x65\x40\x6d\x70\x69\x65\x64" nocase fullword  // cre@mpied in ASCII/UTF-8
    $wide = "\x63\x00\x72\x00\x65\x00\x40\x00\x6d\x00\x70\x00\x69\x00\x65\x00\x64\x00" nocase fullword  // cre@mpied in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_160 {
  meta:
    info = "f@cials"
  strings:
    $ascii = "\x66\x40\x63\x69\x61\x6c\x73" nocase fullword  // f@cials in ASCII/UTF-8
    $wide = "\x66\x00\x40\x00\x63\x00\x69\x00\x61\x00\x6c\x00\x73\x00" nocase fullword  // f@cials in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_161 {
  meta:
    info = "b00bs"
  strings:
    $ascii = "\x62\x30\x30\x62\x73" nocase fullword  // b00bs in ASCII/UTF-8
    $wide = "\x62\x00\x30\x00\x30\x00\x62\x00\x73\x00" nocase fullword  // b00bs in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_165 {
  meta:
    info = "felching"
  strings:
    $ascii = "\x66\x65\x6c\x63\x68\x69\x6e\x67" nocase fullword  // felching in ASCII/UTF-8
    $wide = "\x66\x00\x65\x00\x6c\x00\x63\x00\x68\x00\x69\x00\x6e\x00\x67\x00" nocase fullword  // felching in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_171 {
  meta:
    info = "facefuck"
  strings:
    $ascii1 = "\x66\x61\x63\x65\x66\x75\x63\x6b" nocase fullword  // facefuck in ASCII/UTF-8
    $wide1 = "\x66\x00\x61\x00\x63\x00\x65\x00\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // facefuck in UTF-16LE
    $ascii2 = "\x66\x61\x63\x65\x20\x66\x75\x63\x6b" nocase fullword  // face fuck in ASCII/UTF-8
    $wide2 = "\x66\x00\x61\x00\x63\x00\x65\x00\x20\x00\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // face fuck in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_172 {
  meta:
    info = "skullfuck"
  strings:
    $ascii1 = "\x73\x6b\x75\x6c\x6c\x66\x75\x63\x6b" nocase fullword  // skullfuck in ASCII/UTF-8
    $wide1 = "\x73\x00\x6b\x00\x75\x00\x6c\x00\x6c\x00\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // skullfuck in UTF-16LE
    $ascii2 = "\x73\x6b\x75\x6c\x6c\x20\x66\x75\x63\x6b" nocase fullword  // skull fuck in ASCII/UTF-8
    $wide2 = "\x73\x00\x6b\x00\x75\x00\x6c\x00\x6c\x00\x20\x00\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // skull fuck in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_173 {
  meta:
    info = "titfuck"
  strings:
    $ascii1 = "\x74\x69\x74\x66\x75\x63\x6b" nocase fullword  // titfuck in ASCII/UTF-8
    $wide1 = "\x74\x00\x69\x00\x74\x00\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // titfuck in UTF-16LE
    $ascii2 = "\x74\x69\x74\x20\x66\x75\x63\x6b" nocase fullword  // tit fuck in ASCII/UTF-8
    $wide2 = "\x74\x00\x69\x00\x74\x00\x20\x00\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // tit fuck in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_174 {
  meta:
    info = "buttfuck"
  strings:
    $ascii1 = "\x62\x75\x74\x74\x66\x75\x63\x6b" nocase fullword  // buttfuck in ASCII/UTF-8
    $wide1 = "\x62\x00\x75\x00\x74\x00\x74\x00\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // buttfuck in UTF-16LE
    $ascii2 = "\x62\x75\x74\x74\x20\x66\x75\x63\x6b" nocase fullword  // butt fuck in ASCII/UTF-8
    $wide2 = "\x62\x00\x75\x00\x74\x00\x74\x00\x20\x00\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // butt fuck in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_175 {
  meta:
    info = "assfuck"
  strings:
    $ascii1 = "\x61\x73\x73\x66\x75\x63\x6b" nocase fullword  // assfuck in ASCII/UTF-8
    $wide1 = "\x61\x00\x73\x00\x73\x00\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // assfuck in UTF-16LE
    $ascii2 = "\x61\x73\x73\x20\x66\x75\x63\x6b" nocase fullword  // ass fuck in ASCII/UTF-8
    $wide2 = "\x61\x00\x73\x00\x73\x00\x20\x00\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // ass fuck in UTF-16LE
  condition:
    any of them
}

rule content_en_language_nsfw_177 {
  meta:
    info = "throatfuck"
  strings:
    $ascii = "\x74\x68\x72\x6f\x61\x74\x66\x75\x63\x6b" nocase fullword  // throatfuck in ASCII/UTF-8
    $wide = "\x74\x00\x68\x00\x72\x00\x6f\x00\x61\x00\x74\x00\x66\x00\x75\x00\x63\x00\x6b\x00" nocase fullword  // throatfuck in UTF-16LE
  condition:
    any of them
}


