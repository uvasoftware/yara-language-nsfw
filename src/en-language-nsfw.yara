// Vulgar or otherwise not suitable for work words in english

rule content_en_language_nsfw_1
{
  strings:
    $ =  "2 girls 1 cup"  fullword wide ascii nocase
    $ =  "2g1c"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_2 
{
  strings:
    $ =  "apeshit"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_3 {
  strings:
    $ =  "arsehole"  fullword wide ascii nocase
    $ =  "asshole"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_4 {
  strings:
    $ =  "assmunch"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_7 {
  strings:
    $ =  "ball sack"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_8 {
  strings:
    $ =  "bangbros"  fullword wide ascii nocase
  condition:
    1 of them
}

rule content_en_language_nsfw_11 {
  strings:
    $ =  "bbw"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_12 {
  strings:
    $ =  "bdsm"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_16 {
  strings:
    $ =  "bitch"  fullword wide ascii nocase
    $ =  "bitches"  fullword wide ascii nocase
    $ =  "bitched"  fullword wide ascii nocase
    $ =  "bitching"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_18 {
  strings:
    $ =  "blowjob"  fullword wide ascii nocase
    $ =  "blowjobs"  fullword wide ascii nocase
    $ =  "blow job"  fullword wide ascii nocase
    $ =  "blow jobs"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_19 {
  strings:
    $ =  "blumpkin"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_20 {
  strings:
    $ =  "bollocks"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_21 {
  strings:
    $ =  "boner"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_22 {
  strings:
    $ =  "boob"  fullword wide ascii nocase
    $ =  "boobs"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_23 {
  strings:
    $ =  "booty call"  fullword wide ascii nocase
    $ =  "bootycall"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_24 {
  strings:
    $ =  "brown showers"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_25 {
  strings:
    $ =  "bukkake"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_26 {
  strings:
    $ =  "bulldyke"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_27 {
  strings:
    $ =  "bullshit"  fullword wide ascii nocase
    $ =  "bull shit"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_28 {
  strings:
    $ =  "bung hole"  fullword wide ascii nocase
    $ =  "bunghole"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_29 {
  strings:
    $ =  "busty"  fullword wide ascii nocase
  condition:
    1 of them
}
// rule content_en_language_nsfw_30 {
//   strings:
//     $ =  "butt"  fullword wide ascii nocase
//   condition:
//     1 of them
// }
rule content_en_language_nsfw_31 {
  strings:
    $ =  "buttcheeks"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_32 {
  strings:
    $ =  "butthole"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_33 {
  strings:
    $ =  "camel toe"  fullword wide ascii nocase
    $ =  "cameltoe"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_34 {
  strings:
    $ =  "camgirl"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_35 {
  strings:
    $ =  "camslut"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_36 {
  strings:
    $ =  "camwhore"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_37 {
  strings:
    $ =  "carpet muncher"  fullword wide ascii nocase
    $ =  "carpetmuncher"  fullword wide ascii nocase
    $ =  "carpetmunchers"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_38 {
  strings:
    $ =  "circlejerk"  fullword wide ascii nocase
    $ =  "circlejerks"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_39 {
  strings:
    $ =  "cleveland steamer"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_40 {
  strings:
    $ =  "clit"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_41 {
  strings:
    $ =  "clusterfuck"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_44 {
  strings:
    $ =  "coprolagnia"  fullword wide ascii nocase
    $ =  "coprophilia"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_45 {
  strings:
    $ =  "creampie"  fullword wide ascii nocase
  condition:
    1 of them
}
# high false positive rate: 
# rule content_en_language_nsfw_47 {
#  strings:
#    $ =  "cumming"  fullword wide ascii nocase
#  condition:
#    1 of them
#}
rule content_en_language_nsfw_48 {
  strings:
    $ =  "cunnilingus"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_49 {
  strings:
    $ =  "cunt"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_50 {
  strings:
    $ =  "darkie"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_51 {
  strings:
    $ =  "dildo"  fullword wide ascii nocase
    $ =  "dildos"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_52 {
  strings:
    $ =  "dingleberries"  fullword wide ascii nocase
    $ =  "dingleberry"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_53 {
  strings:
    $ =  "dirty sanchez"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_54 {
  strings:
    $ =  "dog style"  fullword wide ascii nocase
    $ =  "doggie style"  fullword wide ascii nocase
    $ =  "doggystyle"  fullword wide ascii nocase
  condition:
    1 of them
}  
rule content_en_language_nsfw_58 {
  strings:
    $ =  "faggot"  fullword wide ascii nocase
    $ =  "faggots"  fullword wide ascii nocase
    $ =  "fagot"  fullword wide ascii nocase
    $ =  "fagots"  fullword wide ascii nocase
  condition:
    1 of them
} 
rule content_en_language_nsfw_59 {
  strings:
    $ =  "figging"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_60 {
  strings:
    $ =  "fingerbang"  fullword wide ascii nocase
  condition:
    1 of them
}  
rule content_en_language_nsfw_61 {
  strings:
    $ =  "fingering"  fullword wide ascii nocase
  condition:
    1 of them
} 
rule content_en_language_nsfw_62 {
  strings:
    $ =  "fisting"  fullword wide ascii nocase
  condition:
    1 of them
} 
rule content_en_language_nsfw_63 {
  strings:
    $ =  "footjob"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_64 {
  strings:
    $ =  "frotting"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_65 {
  strings:
    $ =  "fuck"  fullword wide ascii nocase
    $ =  "fucks"  fullword wide ascii nocase
    $ =  "f***"  fullword wide ascii nocase
    $ =  "f****"  fullword wide ascii nocase
    $ =  "fucked"  fullword wide ascii nocase
    $ =  "fucking"  fullword wide ascii nocase
    $ =  "fuckin"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_67 {
  strings:
    $ =  "fucktard"  fullword wide ascii nocase
    $ =  "fucktards"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_68 {
  strings:
    $ =  "fudge packer"  fullword wide ascii nocase
    $ =  "fudgepacker"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_69 {
  strings:
    $ =  "futanari"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_70 {
  strings:
    $ =  "g-spot"  fullword wide ascii nocase
  condition:
    1 of them
}  
rule content_en_language_nsfw_71 {
  strings:
    $ =  "gang bang"  fullword wide ascii nocase
    $ =  "gangbang"  fullword wide ascii nocase
  condition:
    1 of them
}

rule content_en_language_nsfw_73 {
  strings:
    $ =  "god damn"  fullword wide ascii nocase
    $ =  "goddamn"  fullword wide ascii nocase
    $ =  "goddamns"  fullword wide ascii nocase
  condition:
    1 of them
} 
rule content_en_language_nsfw_74 {
  strings:
    $ =  "gokkun"  fullword wide ascii nocase
  condition:
    1 of them
} 
rule content_en_language_nsfw_75 {
  strings:
    $ =  "golden shower"  fullword wide ascii nocase
    $ =  "golden showers"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_76 {
  strings:
    $ =  "goodpoop"  fullword wide ascii nocase
    $ =  "goodpoops"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_77 {
  strings:
    $ =  "hand job"  fullword wide ascii nocase
    $ =  "hand jobs"  fullword wide ascii nocase
    $ =  "handjob"  fullword wide ascii nocase
    $ =  "handjobs"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_78 {
  strings:
    $ =  "honkey"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_81 {
  strings:
    $ =  "humping"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_82 {
  strings:
    $ =  "jack off"  fullword wide ascii nocase
    $ =  "jackoff"  fullword wide ascii nocase
    $ =  "jacking off"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_83 {
  strings:
    $ =  "jail bait"  fullword wide ascii nocase
    $ =  "jailbait"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_84 {
  strings:
    $ =  "jerk off"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_85 {
  strings:
    $ =  "jigaboo"  fullword wide ascii nocase
    $ =  "jiggaboo"  fullword wide ascii nocase
    $ =  "jiggerboo"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_86 {
  strings:
    $ =  "jizz"  fullword wide ascii nocase
    $ =  "jism"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_87 {
  strings:
    $ =  "kinbaku"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_88 {
  strings:
    $ =  "kinkster"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_89 {
  strings:
    $ =  "kinky"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_90 {
  strings:
    $ =  "knobbing"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_91 {
  strings:
    $ =  "make me come"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_92 {
  strings:
    $ =  "menage a trois"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_93 {
  strings:
    $ =  "milf"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_94 {
  strings:
    $ =  "motherfucker"  fullword wide ascii nocase
    $ =  "motherfuckers"  fullword wide ascii nocase
    $ =  "mother fucker"  fullword wide ascii nocase
    $ =  "mother fuckers"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_95 {
  strings:
    $ =  "mound of venus"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_96 {
  strings:
    $ =  "muff diver"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_97 {
  strings:
    $ =  "muffdiving"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_98 {
  strings:
    $ =  "nawashi"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_99 {
  strings:
    $ =  "octopussy"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_100 {
  strings:
    $ =  "omorashi"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_101 {
  strings:
    $ =  "one cup two girls"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_102 {
  strings:
    $ =  "one guy one jar"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_103 {
  strings:
    $ =  "piece of shit"  fullword wide ascii nocase
    $ =  "pieces of shit"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_104 {
  strings:
    $ =  "piss pig"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_105 {
  strings:
    $ =  "pole smoker"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_106 {
  strings:
    $ =  "ponyplay"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_107 {
  strings:
    $ =  "poon"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_108 {
  strings:
    $ =  "poontang"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_109 {
  strings:
    $ =  "poop chute"  fullword wide ascii nocase
    $ =  "poopchute"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_110 {
  strings:
    $ =  "prince albert piercing"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_112 {
  strings:
    $ =  "punany"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_113 {
  strings:
    $ =  "pussy"  fullword wide ascii nocase
    $ =  "pussies"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_114 {
  strings:
    $ =  "queaf"  fullword wide ascii nocase
    $ =  "queef"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_115 {
  strings:
    $ =  "quim"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_116 {
  strings:
    $ =  "raging boner"  fullword wide ascii nocase
    $ =  "raging boners"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_117 {
  strings:
    $ =  "reverse cowgirl"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_118 {
  strings:
    $ =  "rimjob"  fullword wide ascii nocase
    $ =  "rimming"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_119 {
  strings:
    $ =  "rirosy palmm"  fullword wide ascii nocase
    $ =  "rosy palm and her 5 sisters"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_120 {
  strings:
    $ =  "rusty trombone"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_121 {
  strings:
    $ =  "schlong"  fullword wide ascii nocase
    $ =  "schlongs"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_122 {
  strings:
    $ =  "shaved beaver"  fullword wide ascii nocase
    $ =  "shaved beavers"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_123 {
  strings:
    $ =  "shemale"  fullword wide ascii nocase
    $ =  "shemales"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_124 {
  strings:
    $ =  "shibari"  fullword wide ascii nocase
    $ =  "shibaris"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_125 {
  strings:
    $ =  "shit"  fullword wide ascii nocase
    $ =  "shits"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_126 {
  strings:
    $ =  "shota"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_127 {
  strings:
    $ =  "slut"  fullword wide ascii nocase
    $ =  "sluts"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_128 {
  strings:
    $ =  "smut"  fullword wide ascii nocase
  condition:
    1 of them
}

rule content_en_language_nsfw_130 {
  strings:
    $ =  "splooge"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_131 {
  strings:
    $ =  "spooge"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_133 {
  strings:
    $ =  "spunk"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_134 {
  strings:
    $ =  "strapon"  fullword wide ascii nocase
    $ =  "strap on"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_135 {
  strings:
    $ =  "strappado"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_136 {
  strings:
    $ =  "tea bagging"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_137 {
  strings:
    $ =  "threesome"  fullword wide ascii nocase
    $ =  "threesomes"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_138 {
  strings:
    $ =  "tranny"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_139 {
  strings:
    $ =  "tub girl"  fullword wide ascii nocase
    $ =  "tubgirl"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_140 {
  strings:
    $ =  "tushy"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_141 {
  strings:
    $ =  "twat"  fullword wide ascii nocase
    $ =  "twats"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_142 {
  strings:
    $ =  "upskirt"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_143 {
  strings:
    $ =  "vibrator"  fullword wide ascii nocase
    $ =  "vibrators"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_144 {
  strings:
    $ =  "wank"  fullword wide ascii nocase
    $ =  "wanker"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_145 {
  strings:
    $ =  "yaoi"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_146 {
  strings:
    $ =  "yiffy"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_147 {
  strings:
    $ =  "wrinkled starfish"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_148 {
  strings:
    $ =  "yellow showers"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_149 {
  strings:
    $ =  "donkey punch"  fullword wide ascii nocase
    $ =  "donkey punches"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_150 {
  strings:
    $ =  "goregasm"  fullword wide ascii nocase
    $ =  "goregasms"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_151{
  strings:
    $ =  "hot carl"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_152 {
  strings:
    $ =  "🖕"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_153 {
  strings:
    $ =  "wet dream"  fullword wide ascii nocase
    $ =  "wet dreams"  fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_154 {
  strings:
    $ = "F@cking" fullword wide ascii nocase
  condition:
    1 of them
}
rule content_en_language_nsfw_155 {
  strings:
    $ = "c0ck" fullword wide ascii nocase
  condition:
    1 of them
}

rule content_en_language_nsfw_156 {
  strings:
    $ = "pu$$y" fullword wide ascii nocase
  condition:
    1 of them
}

rule content_en_language_nsfw_157 {
  strings:
    $ = "$luts" fullword wide ascii nocase
  condition:
    1 of them
}

rule content_en_language_nsfw_158 {
  strings:
    $ = "h00kers" fullword wide ascii nocase
  condition:
    1 of them
}

rule content_en_language_nsfw_159 {
  strings:
    $ = "cre@mpied" fullword wide ascii nocase
  condition:
    1 of them
}

rule content_en_language_nsfw_160 {
  strings:
    $ = "f@cials" fullword wide ascii nocase
  condition:
    1 of them
}

rule content_en_language_nsfw_161 {
  strings:
    $ = "b00bs" fullword wide ascii nocase
  condition:
    1 of them
}
