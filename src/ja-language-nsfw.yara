
rule content_ja_language_nsfw_1 {
  meta:
    info = "3p"
  strings:
    $utf8 = "\x33\x70" nocase
    $sjis = "\x33\x70" nocase
    $wide = "\x33\x00\x70\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_2 {
  meta:
    info = "g スポット"
  strings:
    $utf8 = "\x67\x20\xe3\x82\xb9\xe3\x83\x9d\xe3\x83\x83\xe3\x83\x88" nocase
    $sjis = "\x67\x20\x83\x58\x83\x7c\x83\x62\x83\x67" nocase
    $wide = "\x67\x00\x20\x00\x30b9\x00\x30dd\x00\x30c3\x00\x30c8\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_3 {
  meta:
    info = "s ＆ m"
  strings:
    $utf8 = "\x73\x20\xef\xbc\x86\x20\x6d" nocase
    $sjis = "\x73\x20\x81\x95\x20\x6d" nocase
    $wide = "\x73\x00\x20\x00\xff06\x00\x20\x00\x6d\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_4 {
  meta:
    info = "sm"
  strings:
    $utf8 = "\x73\x6d" nocase
    $sjis = "\x73\x6d" nocase
    $wide = "\x73\x00\x6d\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_5 {
  meta:
    info = "sm女王"
  strings:
    $utf8 = "\x73\x6d\xe5\xa5\xb3\xe7\x8e\x8b" nocase
    $sjis = "\x73\x6d\x8f\x97\x89\xa4" nocase
    $wide = "\x73\x00\x6d\x00\x5973\x00\x738b\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_7 {
  meta:
    info = "糞"
  strings:
    $utf8 = "\xe7\xb3\x9e" nocase
    $sjis = "\x95\xb3" nocase
    $wide = "\x7cde\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_8 {
  meta:
    info = "膣"
  strings:
    $utf8 = "\xe8\x86\xa3" nocase
    $sjis = "\xe4\x53" nocase
    $wide = "\x81a3\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_9 {
  meta:
    info = "裸"
  strings:
    $utf8 = "\xe8\xa3\xb8" nocase
    $sjis = "\x97\x87" nocase
    $wide = "\x88f8\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_10 {
  meta:
    info = "お尻"
  strings:
    $utf8 = "\xe3\x81\x8a\xe5\xb0\xbb" nocase
    $sjis = "\x82\xa8\x90\x4b" nocase
    $wide = "\x304a\x00\x5c3b\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_11 {
  meta:
    info = "なめ"
  strings:
    $utf8 = "\xe3\x81\xaa\xe3\x82\x81" nocase
    $sjis = "\x82\xc8\x82\xdf" nocase
    $wide = "\x306a\x00\x3081\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_12 {
  meta:
    info = "グロ"
  strings:
    $utf8 = "\xe3\x82\xb0\xe3\x83\xad" nocase
    $sjis = "\x83\x4f\x83\x8d" nocase
    $wide = "\x30b0\x00\x30ed\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_13 {
  meta:
    info = "デブ"
  strings:
    $utf8 = "\xe3\x83\x87\xe3\x83\x96" nocase
    $sjis = "\x83\x66\x83\x75" nocase
    $wide = "\x30c7\x00\x30d6\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_14 {
  meta:
    info = "ホモ"
  strings:
    $utf8 = "\xe3\x83\x9b\xe3\x83\xa2" nocase
    $sjis = "\x83\x7a\x83\x82" nocase
    $wide = "\x30db\x00\x30e2\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_15 {
  meta:
    info = "両刀"
  strings:
    $utf8 = "\xe4\xb8\xa1\xe5\x88\x80" nocase
    $sjis = "\x97\xbc\x93\x81" nocase
    $wide = "\x4e21\x00\x5200\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_16 {
  meta:
    info = "両性"
  strings:
    $utf8 = "\xe4\xb8\xa1\xe6\x80\xa7" nocase
    $sjis = "\x97\xbc\x90\xab" nocase
    $wide = "\x4e21\x00\x6027\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_17 {
  meta:
    info = "乱交"
  strings:
    $utf8 = "\xe4\xb9\xb1\xe4\xba\xa4" nocase
    $sjis = "\x97\x90\x8c\xf0" nocase
    $wide = "\x4e71\x00\x4ea4\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_18 {
  meta:
    info = "乳首"
  strings:
    $utf8 = "\xe4\xb9\xb3\xe9\xa6\x96" nocase
    $sjis = "\x93\xfb\x8e\xf1" nocase
    $wide = "\x4e73\x00\x9996\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_19 {
  meta:
    info = "二穴"
  strings:
    $utf8 = "\xe4\xba\x8c\xe7\xa9\xb4" nocase
    $sjis = "\x93\xf1\x8c\x8a" nocase
    $wide = "\x4e8c\x00\x7a74\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_20 {
  meta:
    info = "人妻"
  strings:
    $utf8 = "\xe4\xba\xba\xe5\xa6\xbb" nocase
    $sjis = "\x90\x6c\x8d\xc8" nocase
    $wide = "\x4eba\x00\x59bb\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_21 {
  meta:
    info = "人種"
  strings:
    $utf8 = "\xe4\xba\xba\xe7\xa8\xae" nocase
    $sjis = "\x90\x6c\x8e\xed" nocase
    $wide = "\x4eba\x00\x7a2e\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_22 {
  meta:
    info = "剃毛"
  strings:
    $utf8 = "\xe5\x89\x83\xe6\xaf\x9b" nocase
    $sjis = "\x92\xe4\x96\xd1" nocase
    $wide = "\x5243\x00\x6bdb\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_23 {
  meta:
    info = "噴出"
  strings:
    $utf8 = "\xe5\x99\xb4\xe5\x87\xba" nocase
    $sjis = "\x95\xac\x8f\x6f" nocase
    $wide = "\x5674\x00\x51fa\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_24 {
  meta:
    info = "変態"
  strings:
    $utf8 = "\xe5\xa4\x89\xe6\x85\x8b" nocase
    $sjis = "\x95\xcf\x91\xd4" nocase
    $wide = "\x5909\x00\x614b\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_25 {
  meta:
    info = "夢精"
  strings:
    $utf8 = "\xe5\xa4\xa2\xe7\xb2\xbe" nocase
    $sjis = "\x96\xb2\x90\xb8" nocase
    $wide = "\x5922\x00\x7cbe\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_26 {
  meta:
    info = "女装"
  strings:
    $utf8 = "\xe5\xa5\xb3\xe8\xa3\x85" nocase
    $sjis = "\x8f\x97\x91\x95" nocase
    $wide = "\x5973\x00\x88c5\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_27 {
  meta:
    info = "奴隷"
  strings:
    $utf8 = "\xe5\xa5\xb4\xe9\x9a\xb7" nocase
    $sjis = "\x93\x7a\x97\xea" nocase
    $wide = "\x5974\x00\x96b7\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_29 {
  meta:
    info = "宦官"
  strings:
    $utf8 = "\xe5\xae\xa6\xe5\xae\x98" nocase
    $sjis = "\x9b\x81\x8a\xaf" nocase
    $wide = "\x5ba6\x00\x5b98\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_30 {
  meta:
    info = "射精"
  strings:
    $utf8 = "\xe5\xb0\x84\xe7\xb2\xbe" nocase
    $sjis = "\x8e\xcb\x90\xb8" nocase
    $wide = "\x5c04\x00\x7cbe\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_31 {
  meta:
    info = "巨乳"
  strings:
    $utf8 = "\xe5\xb7\xa8\xe4\xb9\xb3" nocase
    $sjis = "\x8b\x90\x93\xfb" nocase
    $wide = "\x5de8\x00\x4e73\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_32 {
  meta:
    info = "巨根"
  strings:
    $utf8 = "\xe5\xb7\xa8\xe6\xa0\xb9" nocase
    $sjis = "\x8b\x90\x8d\xaa" nocase
    $wide = "\x5de8\x00\x6839\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_34 {
  meta:
    info = "性交"
  strings:
    $utf8 = "\xe6\x80\xa7\xe4\xba\xa4" nocase
    $sjis = "\x90\xab\x8c\xf0" nocase
    $wide = "\x6027\x00\x4ea4\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_35 {
  meta:
    info = "拷問"
  strings:
    $utf8 = "\xe6\x8b\xb7\xe5\x95\x8f" nocase
    $sjis = "\x8d\x89\x96\xe2" nocase
    $wide = "\x62f7\x00\x554f\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_36 {
  meta:
    info = "挿入"
  strings:
    $utf8 = "\xe6\x8c\xbf\xe5\x85\xa5" nocase
    $sjis = "\x91\x7d\x93\xfc" nocase
    $wide = "\x633f\x00\x5165\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_37 {
  meta:
    info = "支配"
  strings:
    $utf8 = "\xe6\x94\xaf\xe9\x85\x8d" nocase
    $sjis = "\x8e\x78\x94\x7a" nocase
    $wide = "\x652f\x00\x914d\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_38 {
  meta:
    info = "淫乱"
  strings:
    $utf8 = "\xe6\xb7\xab\xe4\xb9\xb1" nocase
    $sjis = "\x88\xfa\x97\x90" nocase
    $wide = "\x6deb\x00\x4e71\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_39 {
  meta:
    info = "獣姦"
  strings:
    $utf8 = "\xe7\x8d\xa3\xe5\xa7\xa6" nocase
    $sjis = "\x8f\x62\x8a\xad" nocase
    $wide = "\x7363\x00\x59e6\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_40 {
  meta:
    info = "直腸"
  strings:
    $utf8 = "\xe7\x9b\xb4\xe8\x85\xb8" nocase
    $sjis = "\x92\xbc\x92\xb0" nocase
    $wide = "\x76f4\x00\x8178\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_41 {
  meta:
    info = "精液"
  strings:
    $utf8 = "\xe7\xb2\xbe\xe6\xb6\xb2" nocase
    $sjis = "\x90\xb8\x89\x74" nocase
    $wide = "\x7cbe\x00\x6db2\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_42 {
  meta:
    info = "糞便"
  strings:
    $utf8 = "\xe7\xb3\x9e\xe4\xbe\xbf" nocase
    $sjis = "\x95\xb3\x95\xd6" nocase
    $wide = "\x7cde\x00\x4fbf\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_43 {
  meta:
    info = "緊縛"
  strings:
    $utf8 = "\xe7\xb7\x8a\xe7\xb8\x9b" nocase
    $sjis = "\x8b\xd9\x94\x9b" nocase
    $wide = "\x7dca\x00\x7e1b\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_44 {
  meta:
    info = "縛り"
  strings:
    $utf8 = "\xe7\xb8\x9b\xe3\x82\x8a" nocase
    $sjis = "\x94\x9b\x82\xe8" nocase
    $wide = "\x7e1b\x00\x308a\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_45 {
  meta:
    info = "肛門"
  strings:
    $utf8 = "\xe8\x82\x9b\xe9\x96\x80" nocase
    $sjis = "\xe3\xe8\x96\xe5" nocase
    $wide = "\x809b\x00\x9580\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_46 {
  meta:
    info = "脱衣"
  strings:
    $utf8 = "\xe8\x84\xb1\xe8\xa1\xa3" nocase
    $sjis = "\x92\x45\x88\xdf" nocase
    $wide = "\x8131\x00\x8863\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_47 {
  meta:
    info = "覗き"
  strings:
    $utf8 = "\xe8\xa6\x97\xe3\x81\x8d" nocase
    $sjis = "\x94\x60\x82\xab" nocase
    $wide = "\x8997\x00\x304d\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_48 {
  meta:
    info = "誘惑"
  strings:
    $utf8 = "\xe8\xaa\x98\xe6\x83\x91" nocase
    $sjis = "\x97\x55\x98\x66" nocase
    $wide = "\x8a98\x00\x60d1\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_49 {
  meta:
    info = "輪姦"
  strings:
    $utf8 = "\xe8\xbc\xaa\xe5\xa7\xa6" nocase
    $sjis = "\x97\xd6\x8a\xad" nocase
    $wide = "\x8f2a\x00\x59e6\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_50 {
  meta:
    info = "陰毛"
  strings:
    $utf8 = "\xe9\x99\xb0\xe6\xaf\x9b" nocase
    $sjis = "\x89\x41\x96\xd1" nocase
    $wide = "\x9670\x00\x6bdb\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_51 {
  meta:
    info = "おしり"
  strings:
    $utf8 = "\xe3\x81\x8a\xe3\x81\x97\xe3\x82\x8a" nocase
    $sjis = "\x82\xa8\x82\xb5\x82\xe8" nocase
    $wide = "\x304a\x00\x3057\x00\x308a\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_52 {
  meta:
    info = "しばり"
  strings:
    $utf8 = "\xe3\x81\x97\xe3\x81\xb0\xe3\x82\x8a" nocase
    $sjis = "\x82\xb5\x82\xce\x82\xe8" nocase
    $wide = "\x3057\x00\x3070\x00\x308a\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_53 {
  meta:
    info = "ちんこ"
  strings:
    $utf8 = "\xe3\x81\xa1\xe3\x82\x93\xe3\x81\x93" nocase
    $sjis = "\x82\xbf\x82\xf1\x82\xb1" nocase
    $wide = "\x3061\x00\x3093\x00\x3053\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_54 {
  meta:
    info = "まんこ"
  strings:
    $utf8 = "\xe3\x81\xbe\xe3\x82\x93\xe3\x81\x93" nocase
    $sjis = "\x82\xdc\x82\xf1\x82\xb1" nocase
    $wide = "\x307e\x00\x3093\x00\x3053\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_55 {
  meta:
    info = "やおい"
  strings:
    $utf8 = "\xe3\x82\x84\xe3\x81\x8a\xe3\x81\x84" nocase
    $sjis = "\x82\xe2\x82\xa8\x82\xa2" nocase
    $wide = "\x3084\x00\x304a\x00\x3044\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_56 {
  meta:
    info = "アナル"
  strings:
    $utf8 = "\xe3\x82\xa2\xe3\x83\x8a\xe3\x83\xab" nocase
    $sjis = "\x83\x41\x83\x69\x83\x8b" nocase
    $wide = "\x30a2\x00\x30ca\x00\x30eb\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_57 {
  meta:
    info = "エッチ"
  strings:
    $utf8 = "\xe3\x82\xa8\xe3\x83\x83\xe3\x83\x81" nocase
    $sjis = "\x83\x47\x83\x62\x83\x60" nocase
    $wide = "\x30a8\x00\x30c3\x00\x30c1\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_58 {
  meta:
    info = "オカマ"
  strings:
    $utf8 = "\xe3\x82\xaa\xe3\x82\xab\xe3\x83\x9e" nocase
    $sjis = "\x83\x49\x83\x4a\x83\x7d" nocase
    $wide = "\x30aa\x00\x30ab\x00\x30de\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_59 {
  meta:
    info = "オシリ"
  strings:
    $utf8 = "\xe3\x82\xaa\xe3\x82\xb7\xe3\x83\xaa" nocase
    $sjis = "\x83\x49\x83\x56\x83\x8a" nocase
    $wide = "\x30aa\x00\x30b7\x00\x30ea\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_60 {
  meta:
    info = "カント"
  strings:
    $utf8 = "\xe3\x82\xab\xe3\x83\xb3\xe3\x83\x88" nocase
    $sjis = "\x83\x4a\x83\x93\x83\x67" nocase
    $wide = "\x30ab\x00\x30f3\x00\x30c8\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_61 {
  meta:
    info = "ニガー"
  strings:
    $utf8 = "\xe3\x83\x8b\xe3\x82\xac\xe3\x83\xbc" nocase
    $sjis = "\x83\x6a\x83\x4b\x81\x5b" nocase
    $wide = "\x30cb\x00\x30ac\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_62 {
  meta:
    info = "ヌード"
  strings:
    $utf8 = "\xe3\x83\x8c\xe3\x83\xbc\xe3\x83\x89" nocase
    $sjis = "\x83\x6b\x81\x5b\x83\x68" nocase
    $wide = "\x30cc\x00\x30fc\x00\x30c9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_63 {
  meta:
    info = "ビッチ"
  strings:
    $utf8 = "\xe3\x83\x93\xe3\x83\x83\xe3\x83\x81" nocase
    $sjis = "\x83\x72\x83\x62\x83\x60" nocase
    $wide = "\x30d3\x00\x30c3\x00\x30c1\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_64 {
  meta:
    info = "フック"
  strings:
    $utf8 = "\xe3\x83\x95\xe3\x83\x83\xe3\x82\xaf" nocase
    $sjis = "\x83\x74\x83\x62\x83\x4e" nocase
    $wide = "\x30d5\x00\x30c3\x00\x30af\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_65 {
  meta:
    info = "ペニス"
  strings:
    $utf8 = "\xe3\x83\x9a\xe3\x83\x8b\xe3\x82\xb9" nocase
    $sjis = "\x83\x79\x83\x6a\x83\x58" nocase
    $wide = "\x30da\x00\x30cb\x00\x30b9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_66 {
  meta:
    info = "ポルノ"
  strings:
    $utf8 = "\xe3\x83\x9d\xe3\x83\xab\xe3\x83\x8e" nocase
    $sjis = "\x83\x7c\x83\x8b\x83\x6d" nocase
    $wide = "\x30dd\x00\x30eb\x00\x30ce\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_67 {
  meta:
    info = "ラバー"
  strings:
    $utf8 = "\xe3\x83\xa9\xe3\x83\x90\xe3\x83\xbc" nocase
    $sjis = "\x83\x89\x83\x6f\x81\x5b" nocase
    $wide = "\x30e9\x00\x30d0\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_68 {
  meta:
    info = "レイプ"
  strings:
    $utf8 = "\xe3\x83\xac\xe3\x82\xa4\xe3\x83\x97" nocase
    $sjis = "\x83\x8c\x83\x43\x83\x76" nocase
    $wide = "\x30ec\x00\x30a4\x00\x30d7\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_69 {
  meta:
    info = "中出し"
  strings:
    $utf8 = "\xe4\xb8\xad\xe5\x87\xba\xe3\x81\x97" nocase
    $sjis = "\x92\x86\x8f\x6f\x82\xb5" nocase
    $wide = "\x4e2d\x00\x51fa\x00\x3057\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_70 {
  meta:
    info = "売春婦"
  strings:
    $utf8 = "\xe5\xa3\xb2\xe6\x98\xa5\xe5\xa9\xa6" nocase
    $sjis = "\x94\x84\x8f\x74\x95\x77" nocase
    $wide = "\x58f2\x00\x6625\x00\x5a66\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_71 {
  meta:
    info = "大陰唇"
  strings:
    $utf8 = "\xe5\xa4\xa7\xe9\x99\xb0\xe5\x94\x87" nocase
    $sjis = "\x91\xe5\x89\x41\x90\x4f" nocase
    $wide = "\x5927\x00\x9670\x00\x5507\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_73 {
  meta:
    info = "女王様"
  strings:
    $utf8 = "\xe5\xa5\xb3\xe7\x8e\x8b\xe6\xa7\x98" nocase
    $sjis = "\x8f\x97\x89\xa4\x97\x6c" nocase
    $wide = "\x5973\x00\x738b\x00\x69d8\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_74 {
  meta:
    info = "強姦犯"
  strings:
    $utf8 = "\xe5\xbc\xb7\xe5\xa7\xa6\xe7\x8a\xaf" nocase
    $sjis = "\x8b\xad\x8a\xad\x94\xc6" nocase
    $wide = "\x5f37\x00\x59e6\x00\x72af\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_75 {
  meta:
    info = "後背位"
  strings:
    $utf8 = "\xe5\xbe\x8c\xe8\x83\x8c\xe4\xbd\x8d" nocase
    $sjis = "\x8c\xe3\x94\x77\x88\xca" nocase
    $wide = "\x5f8c\x00\x80cc\x00\x4f4d\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_76 {
  meta:
    info = "手コキ"
  strings:
    $utf8 = "\xe6\x89\x8b\xe3\x82\xb3\xe3\x82\xad" nocase
    $sjis = "\x8e\xe8\x83\x52\x83\x4c" nocase
    $wide = "\x624b\x00\x30b3\x00\x30ad\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_77 {
  meta:
    info = "正常位"
  strings:
    $utf8 = "\xe6\xad\xa3\xe5\xb8\xb8\xe4\xbd\x8d" nocase
    $sjis = "\x90\xb3\x8f\xed\x88\xca" nocase
    $wide = "\x6b63\x00\x5e38\x00\x4f4d\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_78 {
  meta:
    info = "殺し方"
  strings:
    $utf8 = "\xe6\xae\xba\xe3\x81\x97\xe6\x96\xb9" nocase
    $sjis = "\x8e\x45\x82\xb5\x95\xfb" nocase
    $wide = "\x6bba\x00\x3057\x00\x65b9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_79 {
  meta:
    info = "毛深い"
  strings:
    $utf8 = "\xe6\xaf\x9b\xe6\xb7\xb1\xe3\x81\x84" nocase
    $sjis = "\x96\xd1\x90\x5b\x82\xa2" nocase
    $wide = "\x6bdb\x00\x6df1\x00\x3044\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_80 {
  meta:
    info = "玉なめ"
  strings:
    $utf8 = "\xe7\x8e\x89\xe3\x81\xaa\xe3\x82\x81" nocase
    $sjis = "\x8b\xca\x82\xc8\x82\xdf" nocase
    $wide = "\x7389\x00\x306a\x00\x3081\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_81 {
  meta:
    info = "玉舐め"
  strings:
    $utf8 = "\xe7\x8e\x89\xe8\x88\x90\xe3\x82\x81" nocase
    $sjis = "\x8b\xca\xe4\x72\x82\xdf" nocase
    $wide = "\x7389\x00\x8210\x00\x3081\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_82 {
  meta:
    info = "生殖器"
  strings:
    $utf8 = "\xe7\x94\x9f\xe6\xae\x96\xe5\x99\xa8" nocase
    $sjis = "\x90\xb6\x90\x42\x8a\xed" nocase
    $wide = "\x751f\x00\x6b96\x00\x5668\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_83 {
  meta:
    info = "貞操帯"
  strings:
    $utf8 = "\xe8\xb2\x9e\xe6\x93\x8d\xe5\xb8\xaf" nocase
    $sjis = "\x92\xe5\x91\x80\x91\xd1" nocase
    $wide = "\x8c9e\x00\x64cd\x00\x5e2f\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_84 {
  meta:
    info = "革抑制"
  strings:
    $utf8 = "\xe9\x9d\xa9\xe6\x8a\x91\xe5\x88\xb6" nocase
    $sjis = "\x8a\x76\x97\x7d\x90\xa7" nocase
    $wide = "\x9769\x00\x6291\x00\x5236\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_85 {
  meta:
    info = "騎上位"
  strings:
    $utf8 = "\xe9\xa8\x8e\xe4\xb8\x8a\xe4\xbd\x8d" nocase
    $sjis = "\x8b\x52\x8f\xe3\x88\xca" nocase
    $wide = "\x9a0e\x00\x4e0a\x00\x4f4d\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_86 {
  meta:
    info = "いたずら"
  strings:
    $utf8 = "\xe3\x81\x84\xe3\x81\x9f\xe3\x81\x9a\xe3\x82\x89" nocase
    $sjis = "\x82\xa2\x82\xbd\x82\xb8\x82\xe7" nocase
    $wide = "\x3044\x00\x305f\x00\x305a\x00\x3089\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_87 {
  meta:
    info = "おしっこ"
  strings:
    $utf8 = "\xe3\x81\x8a\xe3\x81\x97\xe3\x81\xa3\xe3\x81\x93" nocase
    $sjis = "\x82\xa8\x82\xb5\x82\xc1\x82\xb1" nocase
    $wide = "\x304a\x00\x3057\x00\x3063\x00\x3053\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_88 {
  meta:
    info = "おっぱい"
  strings:
    $utf8 = "\xe3\x81\x8a\xe3\x81\xa3\xe3\x81\xb1\xe3\x81\x84" nocase
    $sjis = "\x82\xa8\x82\xc1\x82\xcf\x82\xa2" nocase
    $wide = "\x304a\x00\x3063\x00\x3071\x00\x3044\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_89 {
  meta:
    info = "おもらし"
  strings:
    $utf8 = "\xe3\x81\x8a\xe3\x82\x82\xe3\x82\x89\xe3\x81\x97" nocase
    $sjis = "\x82\xa8\x82\xe0\x82\xe7\x82\xb5" nocase
    $wide = "\x304a\x00\x3082\x00\x3089\x00\x3057\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_90 {
  meta:
    info = "ふたなり"
  strings:
    $utf8 = "\xe3\x81\xb5\xe3\x81\x9f\xe3\x81\xaa\xe3\x82\x8a" nocase
    $sjis = "\x82\xd3\x82\xbd\x82\xc8\x82\xe8" nocase
    $wide = "\x3075\x00\x305f\x00\x306a\x00\x308a\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_91 {
  meta:
    info = "ぶっかけ"
  strings:
    $utf8 = "\xe3\x81\xb6\xe3\x81\xa3\xe3\x81\x8b\xe3\x81\x91" nocase
    $sjis = "\x82\xd4\x82\xc1\x82\xa9\x82\xaf" nocase
    $wide = "\x3076\x00\x3063\x00\x304b\x00\x3051\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_92 {
  meta:
    info = "やりまん"
  strings:
    $utf8 = "\xe3\x82\x84\xe3\x82\x8a\xe3\x81\xbe\xe3\x82\x93" nocase
    $sjis = "\x82\xe2\x82\xe8\x82\xdc\x82\xf1" nocase
    $wide = "\x3084\x00\x308a\x00\x307e\x00\x3093\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_93 {
  meta:
    info = "オッパイ"
  strings:
    $utf8 = "\xe3\x82\xaa\xe3\x83\x83\xe3\x83\x91\xe3\x82\xa4" nocase
    $sjis = "\x83\x49\x83\x62\x83\x70\x83\x43" nocase
    $wide = "\x30aa\x00\x30c3\x00\x30d1\x00\x30a4\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_94 {
  meta:
    info = "オナニー"
  strings:
    $utf8 = "\xe3\x82\xaa\xe3\x83\x8a\xe3\x83\x8b\xe3\x83\xbc" nocase
    $sjis = "\x83\x49\x83\x69\x83\x6a\x81\x5b" nocase
    $wide = "\x30aa\x00\x30ca\x00\x30cb\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_95 {
  meta:
    info = "オマンコ"
  strings:
    $utf8 = "\xe3\x82\xaa\xe3\x83\x9e\xe3\x83\xb3\xe3\x82\xb3" nocase
    $sjis = "\x83\x49\x83\x7d\x83\x93\x83\x52" nocase
    $wide = "\x30aa\x00\x30de\x00\x30f3\x00\x30b3\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_96 {
  meta:
    info = "コカイン"
  strings:
    $utf8 = "\xe3\x82\xb3\xe3\x82\xab\xe3\x82\xa4\xe3\x83\xb3" nocase
    $sjis = "\x83\x52\x83\x4a\x83\x43\x83\x93" nocase
    $wide = "\x30b3\x00\x30ab\x00\x30a4\x00\x30f3\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_97 {
  meta:
    info = "ゴックン"
  strings:
    $utf8 = "\xe3\x82\xb4\xe3\x83\x83\xe3\x82\xaf\xe3\x83\xb3" nocase
    $sjis = "\x83\x53\x83\x62\x83\x4e\x83\x93" nocase
    $wide = "\x30b4\x00\x30c3\x00\x30af\x00\x30f3\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_98 {
  meta:
    info = "スカトロ"
  strings:
    $utf8 = "\xe3\x82\xb9\xe3\x82\xab\xe3\x83\x88\xe3\x83\xad" nocase
    $sjis = "\x83\x58\x83\x4a\x83\x67\x83\x8d" nocase
    $wide = "\x30b9\x00\x30ab\x00\x30c8\x00\x30ed\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_99 {
  meta:
    info = "スラット"
  strings:
    $utf8 = "\xe3\x82\xb9\xe3\x83\xa9\xe3\x83\x83\xe3\x83\x88" nocase
    $sjis = "\x83\x58\x83\x89\x83\x62\x83\x67" nocase
    $wide = "\x30b9\x00\x30e9\x00\x30c3\x00\x30c8\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_100 {
  meta:
    info = "スリット"
  strings:
    $utf8 = "\xe3\x82\xb9\xe3\x83\xaa\xe3\x83\x83\xe3\x83\x88" nocase
    $sjis = "\x83\x58\x83\x8a\x83\x62\x83\x67" nocase
    $wide = "\x30b9\x00\x30ea\x00\x30c3\x00\x30c8\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_101 {
  meta:
    info = "セックス"
  strings:
    $utf8 = "\xe3\x82\xbb\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9" nocase
    $sjis = "\x83\x5a\x83\x62\x83\x4e\x83\x58" nocase
    $wide = "\x30bb\x00\x30c3\x00\x30af\x00\x30b9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_102 {
  meta:
    info = "ソドミー"
  strings:
    $utf8 = "\xe3\x82\xbd\xe3\x83\x89\xe3\x83\x9f\xe3\x83\xbc" nocase
    $sjis = "\x83\x5c\x83\x68\x83\x7e\x81\x5b" nocase
    $wide = "\x30bd\x00\x30c9\x00\x30df\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_103 {
  meta:
    info = "ディック"
  strings:
    $utf8 = "\xe3\x83\x87\xe3\x82\xa3\xe3\x83\x83\xe3\x82\xaf" nocase
    $sjis = "\x83\x66\x83\x42\x83\x62\x83\x4e" nocase
    $wide = "\x30c7\x00\x30a3\x00\x30c3\x00\x30af\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_104 {
  meta:
    info = "ディルド"
  strings:
    $utf8 = "\xe3\x83\x87\xe3\x82\xa3\xe3\x83\xab\xe3\x83\x89" nocase
    $sjis = "\x83\x66\x83\x42\x83\x8b\x83\x68" nocase
    $wide = "\x30c7\x00\x30a3\x00\x30eb\x00\x30c9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_105 {
  meta:
    info = "パイパン"
  strings:
    $utf8 = "\xe3\x83\x91\xe3\x82\xa4\xe3\x83\x91\xe3\x83\xb3" nocase
    $sjis = "\x83\x70\x83\x43\x83\x70\x83\x93" nocase
    $wide = "\x30d1\x00\x30a4\x00\x30d1\x00\x30f3\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_106 {
  meta:
    info = "ファック"
  strings:
    $utf8 = "\xe3\x83\x95\xe3\x82\xa1\xe3\x83\x83\xe3\x82\xaf" nocase
    $sjis = "\x83\x74\x83\x40\x83\x62\x83\x4e" nocase
    $wide = "\x30d5\x00\x30a1\x00\x30c3\x00\x30af\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_107 {
  meta:
    info = "フィスト"
  strings:
    $utf8 = "\xe3\x83\x95\xe3\x82\xa3\xe3\x82\xb9\xe3\x83\x88" nocase
    $sjis = "\x83\x74\x83\x42\x83\x58\x83\x67" nocase
    $wide = "\x30d5\x00\x30a3\x00\x30b9\x00\x30c8\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_109 {
  meta:
    info = "ロリータ"
  strings:
    $utf8 = "\xe3\x83\xad\xe3\x83\xaa\xe3\x83\xbc\xe3\x82\xbf" nocase
    $sjis = "\x83\x8d\x83\x8a\x81\x5b\x83\x5e" nocase
    $wide = "\x30ed\x00\x30ea\x00\x30fc\x00\x30bf\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_110 {
  meta:
    info = "ローター"
  strings:
    $utf8 = "\xe3\x83\xad\xe3\x83\xbc\xe3\x82\xbf\xe3\x83\xbc" nocase
    $sjis = "\x83\x8d\x81\x5b\x83\x5e\x81\x5b" nocase
    $wide = "\x30ed\x00\x30fc\x00\x30bf\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_111 {
  meta:
    info = "両性具有"
  strings:
    $utf8 = "\xe4\xb8\xa1\xe6\x80\xa7\xe5\x85\xb7\xe6\x9c\x89" nocase
    $sjis = "\x97\xbc\x90\xab\x8b\xef\x97\x4c" nocase
    $wide = "\x4e21\x00\x6027\x00\x5177\x00\x6709\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_112 {
  meta:
    info = "勃起する"
  strings:
    $utf8 = "\xe5\x8b\x83\xe8\xb5\xb7\xe3\x81\x99\xe3\x82\x8b" nocase
    $sjis = "\x96\x75\x8b\x4e\x82\xb7\x82\xe9" nocase
    $wide = "\x52c3\x00\x8d77\x00\x3059\x00\x308b\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_113 {
  meta:
    info = "女子高生"
  strings:
    $utf8 = "\xe5\xa5\xb3\xe5\xad\x90\xe9\xab\x98\xe7\x94\x9f" nocase
    $sjis = "\x8f\x97\x8e\x71\x8d\x82\x90\xb6" nocase
    $wide = "\x5973\x00\x5b50\x00\x9ad8\x00\x751f\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_114 {
  meta:
    info = "平手打ち"
  strings:
    $utf8 = "\xe5\xb9\xb3\xe6\x89\x8b\xe6\x89\x93\xe3\x81\xa1" nocase
    $sjis = "\x95\xbd\x8e\xe8\x91\xc5\x82\xbf" nocase
    $wide = "\x5e73\x00\x624b\x00\x6253\x00\x3061\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_115 {
  meta:
    info = "殺人事件"
  strings:
    $utf8 = "\xe6\xae\xba\xe4\xba\xba\xe4\xba\x8b\xe4\xbb\xb6" nocase
    $sjis = "\x8e\x45\x90\x6c\x8e\x96\x8c\x8f" nocase
    $wide = "\x6bba\x00\x4eba\x00\x4e8b\x00\x4ef6\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_116 {
  meta:
    info = "殺人方法"
  strings:
    $utf8 = "\xe6\xae\xba\xe4\xba\xba\xe6\x96\xb9\xe6\xb3\x95" nocase
    $sjis = "\x8e\x45\x90\x6c\x95\xfb\x96\x40" nocase
    $wide = "\x6bba\x00\x4eba\x00\x65b9\x00\x6cd5\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_117 {
  meta:
    info = "潮吹き女"
  strings:
    $utf8 = "\xe6\xbd\xae\xe5\x90\xb9\xe3\x81\x8d\xe5\xa5\xb3" nocase
    $sjis = "\x92\xaa\x90\x81\x82\xab\x8f\x97" nocase
    $wide = "\x6f6e\x00\x5439\x00\x304d\x00\x5973\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_118 {
  meta:
    info = "自己愛性"
  strings:
    $utf8 = "\xe8\x87\xaa\xe5\xb7\xb1\xe6\x84\x9b\xe6\x80\xa7" nocase
    $sjis = "\x8e\xa9\x8c\xc8\x88\xa4\x90\xab" nocase
    $wide = "\x81ea\x00\x5df1\x00\x611b\x00\x6027\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_119 {
  meta:
    info = "裸の女性"
  strings:
    $utf8 = "\xe8\xa3\xb8\xe3\x81\xae\xe5\xa5\xb3\xe6\x80\xa7" nocase
    $sjis = "\x97\x87\x82\xcc\x8f\x97\x90\xab" nocase
    $wide = "\x88f8\x00\x306e\x00\x5973\x00\x6027\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_120 {
  meta:
    info = "足フェチ"
  strings:
    $utf8 = "\xe8\xb6\xb3\xe3\x83\x95\xe3\x82\xa7\xe3\x83\x81" nocase
    $sjis = "\x91\xab\x83\x74\x83\x46\x83\x60" nocase
    $wide = "\x8db3\x00\x30d5\x00\x30a7\x00\x30c1\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_121 {
  meta:
    info = "近親相姦"
  strings:
    $utf8 = "\xe8\xbf\x91\xe8\xa6\xaa\xe7\x9b\xb8\xe5\xa7\xa6" nocase
    $sjis = "\x8b\xdf\x90\x65\x91\x8a\x8a\xad" nocase
    $wide = "\x8fd1\x00\x89aa\x00\x76f8\x00\x59e6\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_122 {
  meta:
    info = "プリンス アルバート ピアス"
  strings:
    $utf8 = "\xe3\x83\x97\xe3\x83\xaa\xe3\x83\xb3\xe3\x82\xb9\x20\xe3\x82\xa2\xe3\x83\xab\xe3\x83\x90\xe3\x83\xbc\xe3\x83\x88\x20\xe3\x83\x94\xe3\x82\xa2\xe3\x82\xb9" nocase
    $sjis = "\x83\x76\x83\x8a\x83\x93\x83\x58\x20\x83\x41\x83\x8b\x83\x6f\x81\x5b\x83\x67\x20\x83\x73\x83\x41\x83\x58" nocase
    $wide = "\x30d7\x00\x30ea\x00\x30f3\x00\x30b9\x00\x20\x00\x30a2\x00\x30eb\x00\x30d0\x00\x30fc\x00\x30c8\x00\x20\x00\x30d4\x00\x30a2\x00\x30b9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_123 {
  meta:
    info = "ぽっちゃり"
  strings:
    $utf8 = "\xe3\x81\xbd\xe3\x81\xa3\xe3\x81\xa1\xe3\x82\x83\xe3\x82\x8a" nocase
    $sjis = "\x82\xdb\x82\xc1\x82\xbf\x82\xe1\x82\xe8" nocase
    $wide = "\x307d\x00\x3063\x00\x3061\x00\x3083\x00\x308a\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_124 {
  meta:
    info = "アスホール"
  strings:
    $utf8 = "\xe3\x82\xa2\xe3\x82\xb9\xe3\x83\x9b\xe3\x83\xbc\xe3\x83\xab" nocase
    $sjis = "\x83\x41\x83\x58\x83\x7a\x81\x5b\x83\x8b" nocase
    $wide = "\x30a2\x00\x30b9\x00\x30db\x00\x30fc\x00\x30eb\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_125 {
  meta:
    info = "イラマチオ"
  strings:
    $utf8 = "\xe3\x82\xa4\xe3\x83\xa9\xe3\x83\x9e\xe3\x83\x81\xe3\x82\xaa" nocase
    $sjis = "\x83\x43\x83\x89\x83\x7d\x83\x60\x83\x49" nocase
    $wide = "\x30a4\x00\x30e9\x00\x30de\x00\x30c1\x00\x30aa\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_126 {
  meta:
    info = "エスコート"
  strings:
    $utf8 = "\xe3\x82\xa8\xe3\x82\xb9\xe3\x82\xb3\xe3\x83\xbc\xe3\x83\x88" nocase
    $sjis = "\x83\x47\x83\x58\x83\x52\x81\x5b\x83\x67" nocase
    $wide = "\x30a8\x00\x30b9\x00\x30b3\x00\x30fc\x00\x30c8\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_127 {
  meta:
    info = "オーガズム"
  strings:
    $utf8 = "\xe3\x82\xaa\xe3\x83\xbc\xe3\x82\xac\xe3\x82\xba\xe3\x83\xa0" nocase
    $sjis = "\x83\x49\x81\x5b\x83\x4b\x83\x59\x83\x80" nocase
    $wide = "\x30aa\x00\x30fc\x00\x30ac\x00\x30ba\x00\x30e0\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_128 {
  meta:
    info = "クリトリス"
  strings:
    $utf8 = "\xe3\x82\xaf\xe3\x83\xaa\xe3\x83\x88\xe3\x83\xaa\xe3\x82\xb9" nocase
    $sjis = "\x83\x4e\x83\x8a\x83\x67\x83\x8a\x83\x58" nocase
    $wide = "\x30af\x00\x30ea\x00\x30c8\x00\x30ea\x00\x30b9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_129 {
  meta:
    info = "ゲイの男性"
  strings:
    $utf8 = "\xe3\x82\xb2\xe3\x82\xa4\xe3\x81\xae\xe7\x94\xb7\xe6\x80\xa7" nocase
    $sjis = "\x83\x51\x83\x43\x82\xcc\x92\x6a\x90\xab" nocase
    $wide = "\x30b2\x00\x30a4\x00\x306e\x00\x7537\x00\x6027\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_130 {
  meta:
    info = "ゲイボーイ"
  strings:
    $utf8 = "\xe3\x82\xb2\xe3\x82\xa4\xe3\x83\x9c\xe3\x83\xbc\xe3\x82\xa4" nocase
    $sjis = "\x83\x51\x83\x43\x83\x7b\x81\x5b\x83\x43" nocase
    $wide = "\x30b2\x00\x30a4\x00\x30dc\x00\x30fc\x00\x30a4\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_131 {
  meta:
    info = "サディズム"
  strings:
    $utf8 = "\xe3\x82\xb5\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xba\xe3\x83\xa0" nocase
    $sjis = "\x83\x54\x83\x66\x83\x42\x83\x59\x83\x80" nocase
    $wide = "\x30b5\x00\x30c7\x00\x30a3\x00\x30ba\x00\x30e0\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_132 {
  meta:
    info = "セクシーな"
  strings:
    $utf8 = "\xe3\x82\xbb\xe3\x82\xaf\xe3\x82\xb7\xe3\x83\xbc\xe3\x81\xaa" nocase
    $sjis = "\x83\x5a\x83\x4e\x83\x56\x81\x5b\x82\xc8" nocase
    $wide = "\x30bb\x00\x30af\x00\x30b7\x00\x30fc\x00\x306a\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_133 {
  meta:
    info = "トップレス"
  strings:
    $utf8 = "\xe3\x83\x88\xe3\x83\x83\xe3\x83\x97\xe3\x83\xac\xe3\x82\xb9" nocase
    $sjis = "\x83\x67\x83\x62\x83\x76\x83\x8c\x83\x58" nocase
    $wide = "\x30c8\x00\x30c3\x00\x30d7\x00\x30ec\x00\x30b9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_134 {
  meta:
    info = "ネオ・ナチ"
  strings:
    $utf8 = "\xe3\x83\x8d\xe3\x82\xaa\xe3\x83\xbb\xe3\x83\x8a\xe3\x83\x81" nocase
    $sjis = "\x83\x6c\x83\x49\x81\x45\x83\x69\x83\x60" nocase
    $wide = "\x30cd\x00\x30aa\x00\x30fb\x00\x30ca\x00\x30c1\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_135 {
  meta:
    info = "ハードコア"
  strings:
    $utf8 = "\xe3\x83\x8f\xe3\x83\xbc\xe3\x83\x89\xe3\x82\xb3\xe3\x82\xa2" nocase
    $sjis = "\x83\x6e\x81\x5b\x83\x68\x83\x52\x83\x41" nocase
    $wide = "\x30cf\x00\x30fc\x00\x30c9\x00\x30b3\x00\x30a2\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_136 {
  meta:
    info = "パンティー"
  strings:
    $utf8 = "\xe3\x83\x91\xe3\x83\xb3\xe3\x83\x86\xe3\x82\xa3\xe3\x83\xbc" nocase
    $sjis = "\x83\x70\x83\x93\x83\x65\x83\x42\x81\x5b" nocase
    $wide = "\x30d1\x00\x30f3\x00\x30c6\x00\x30a3\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_137 {
  meta:
    info = "フェラチオ"
  strings:
    $utf8 = "\xe3\x83\x95\xe3\x82\xa7\xe3\x83\xa9\xe3\x83\x81\xe3\x82\xaa" nocase
    $sjis = "\x83\x74\x83\x46\x83\x89\x83\x60\x83\x49" nocase
    $wide = "\x30d5\x00\x30a7\x00\x30e9\x00\x30c1\x00\x30aa\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_138 {
  meta:
    info = "ベアバック"
  strings:
    $utf8 = "\xe3\x83\x99\xe3\x82\xa2\xe3\x83\x90\xe3\x83\x83\xe3\x82\xaf" nocase
    $sjis = "\x83\x78\x83\x41\x83\x6f\x83\x62\x83\x4e" nocase
    $wide = "\x30d9\x00\x30a2\x00\x30d0\x00\x30c3\x00\x30af\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_139 {
  meta:
    info = "ボンテージ"
  strings:
    $utf8 = "\xe3\x83\x9c\xe3\x83\xb3\xe3\x83\x86\xe3\x83\xbc\xe3\x82\xb8" nocase
    $sjis = "\x83\x7b\x83\x93\x83\x65\x81\x5b\x83\x57" nocase
    $wide = "\x30dc\x00\x30f3\x00\x30c6\x00\x30fc\x00\x30b8\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_141 {
  meta:
    info = "レズビアン"
  strings:
    $utf8 = "\xe3\x83\xac\xe3\x82\xba\xe3\x83\x93\xe3\x82\xa2\xe3\x83\xb3" nocase
    $sjis = "\x83\x8c\x83\x59\x83\x72\x83\x41\x83\x93" nocase
    $wide = "\x30ec\x00\x30ba\x00\x30d3\x00\x30a2\x00\x30f3\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_142 {
  meta:
    info = "児童性虐待"
  strings:
    $utf8 = "\xe5\x85\x90\xe7\xab\xa5\xe6\x80\xa7\xe8\x99\x90\xe5\xbe\x85" nocase
    $sjis = "\x8e\x99\x93\xb6\x90\xab\x8b\x73\x91\xd2" nocase
    $wide = "\x5150\x00\x7ae5\x00\x6027\x00\x8650\x00\x5f85\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_143 {
  meta:
    info = "合意の性交"
  strings:
    $utf8 = "\xe5\x90\x88\xe6\x84\x8f\xe3\x81\xae\xe6\x80\xa7\xe4\xba\xa4" nocase
    $sjis = "\x8d\x87\x88\xd3\x82\xcc\x90\xab\x8c\xf0" nocase
    $wide = "\x5408\x00\x610f\x00\x306e\x00\x6027\x00\x4ea4\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_144 {
  meta:
    info = "尿道プレイ"
  strings:
    $utf8 = "\xe5\xb0\xbf\xe9\x81\x93\xe3\x83\x97\xe3\x83\xac\xe3\x82\xa4" nocase
    $sjis = "\x94\x41\x93\xb9\x83\x76\x83\x8c\x83\x43" nocase
    $wide = "\x5c3f\x00\x9053\x00\x30d7\x00\x30ec\x00\x30a4\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_145 {
  meta:
    info = "幼児性愛者"
  strings:
    $utf8 = "\xe5\xb9\xbc\xe5\x85\x90\xe6\x80\xa7\xe6\x84\x9b\xe8\x80\x85" nocase
    $sjis = "\x97\x63\x8e\x99\x90\xab\x88\xa4\x8e\xd2" nocase
    $wide = "\x5e7c\x00\x5150\x00\x6027\x00\x611b\x00\x8005\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_146 {
  meta:
    info = "潮吹き男性"
  strings:
    $utf8 = "\xe6\xbd\xae\xe5\x90\xb9\xe3\x81\x8d\xe7\x94\xb7\xe6\x80\xa7" nocase
    $sjis = "\x92\xaa\x90\x81\x82\xab\x92\x6a\x90\xab" nocase
    $wide = "\x6f6e\x00\x5439\x00\x304d\x00\x7537\x00\x6027\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_147 {
  meta:
    info = "糞尿愛好症"
  strings:
    $utf8 = "\xe7\xb3\x9e\xe5\xb0\xbf\xe6\x84\x9b\xe5\xa5\xbd\xe7\x97\x87" nocase
    $sjis = "\x95\xb3\x94\x41\x88\xa4\x8d\x44\x8f\xc7" nocase
    $wide = "\x7cde\x00\x5c3f\x00\x611b\x00\x597d\x00\x75c7\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_148 {
  meta:
    info = "足を広げる"
  strings:
    $utf8 = "\xe8\xb6\xb3\xe3\x82\x92\xe5\xba\x83\xe3\x81\x92\xe3\x82\x8b" nocase
    $sjis = "\x91\xab\x82\xf0\x8d\x4c\x82\xb0\x82\xe9" nocase
    $wide = "\x8db3\x00\x3092\x00\x5e83\x00\x3052\x00\x308b\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_149 {
  meta:
    info = "セクシーな 10 代"
  strings:
    $utf8 = "\xe3\x82\xbb\xe3\x82\xaf\xe3\x82\xb7\xe3\x83\xbc\xe3\x81\xaa\x20\x31\x30\x20\xe4\xbb\xa3" nocase
    $sjis = "\x83\x5a\x83\x4e\x83\x56\x81\x5b\x82\xc8\x20\x31\x30\x20\x91\xe3" nocase
    $wide = "\x30bb\x00\x30af\x00\x30b7\x00\x30fc\x00\x306a\x00\x20\x00\x31\x00\x30\x00\x20\x00\x4ee3\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_150 {
  meta:
    info = "おしりのあな"
  strings:
    $utf8 = "\xe3\x81\x8a\xe3\x81\x97\xe3\x82\x8a\xe3\x81\xae\xe3\x81\x82\xe3\x81\xaa" nocase
    $sjis = "\x82\xa8\x82\xb5\x82\xe8\x82\xcc\x82\xa0\x82\xc8" nocase
    $wide = "\x304a\x00\x3057\x00\x308a\x00\x306e\x00\x3042\x00\x306a\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_151 {
  meta:
    info = "アナリングス"
  strings:
    $utf8 = "\xe3\x82\xa2\xe3\x83\x8a\xe3\x83\xaa\xe3\x83\xb3\xe3\x82\xb0\xe3\x82\xb9" nocase
    $sjis = "\x83\x41\x83\x69\x83\x8a\x83\x93\x83\x4f\x83\x58" nocase
    $wide = "\x30a2\x00\x30ca\x00\x30ea\x00\x30f3\x00\x30b0\x00\x30b9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_153 {
  meta:
    info = "エクスタシー"
  strings:
    $utf8 = "\xe3\x82\xa8\xe3\x82\xaf\xe3\x82\xb9\xe3\x82\xbf\xe3\x82\xb7\xe3\x83\xbc" nocase
    $sjis = "\x83\x47\x83\x4e\x83\x58\x83\x5e\x83\x56\x81\x5b" nocase
    $wide = "\x30a8\x00\x30af\x00\x30b9\x00\x30bf\x00\x30b7\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_154 {
  meta:
    info = "エロティズム"
  strings:
    $utf8 = "\xe3\x82\xa8\xe3\x83\xad\xe3\x83\x86\xe3\x82\xa3\xe3\x82\xba\xe3\x83\xa0" nocase
    $sjis = "\x83\x47\x83\x8d\x83\x65\x83\x42\x83\x59\x83\x80" nocase
    $wide = "\x30a8\x00\x30ed\x00\x30c6\x00\x30a3\x00\x30ba\x00\x30e0\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_155 {
  meta:
    info = "エロティック"
  strings:
    $utf8 = "\xe3\x82\xa8\xe3\x83\xad\xe3\x83\x86\xe3\x82\xa3\xe3\x83\x83\xe3\x82\xaf" nocase
    $sjis = "\x83\x47\x83\x8d\x83\x65\x83\x42\x83\x62\x83\x4e" nocase
    $wide = "\x30a8\x00\x30ed\x00\x30c6\x00\x30a3\x00\x30c3\x00\x30af\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_156 {
  meta:
    info = "スウィンガー"
  strings:
    $utf8 = "\xe3\x82\xb9\xe3\x82\xa6\xe3\x82\xa3\xe3\x83\xb3\xe3\x82\xac\xe3\x83\xbc" nocase
    $sjis = "\x83\x58\x83\x45\x83\x42\x83\x93\x83\x4b\x81\x5b" nocase
    $wide = "\x30b9\x00\x30a6\x00\x30a3\x00\x30f3\x00\x30ac\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_157 {
  meta:
    info = "スカートの中"
  strings:
    $utf8 = "\xe3\x82\xb9\xe3\x82\xab\xe3\x83\xbc\xe3\x83\x88\xe3\x81\xae\xe4\xb8\xad" nocase
    $sjis = "\x83\x58\x83\x4a\x81\x5b\x83\x67\x82\xcc\x92\x86" nocase
    $wide = "\x30b9\x00\x30ab\x00\x30fc\x00\x30c8\x00\x306e\x00\x4e2d\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_158 {
  meta:
    info = "デートレイプ"
  strings:
    $utf8 = "\xe3\x83\x87\xe3\x83\xbc\xe3\x83\x88\xe3\x83\xac\xe3\x82\xa4\xe3\x83\x97" nocase
    $sjis = "\x83\x66\x81\x5b\x83\x67\x83\x8c\x83\x43\x83\x76" nocase
    $wide = "\x30c7\x00\x30fc\x00\x30c8\x00\x30ec\x00\x30a4\x00\x30d7\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_160 {
  meta:
    info = "プレイボーイ"
  strings:
    $utf8 = "\xe3\x83\x97\xe3\x83\xac\xe3\x82\xa4\xe3\x83\x9c\xe3\x83\xbc\xe3\x82\xa4" nocase
    $sjis = "\x83\x76\x83\x8c\x83\x43\x83\x7b\x81\x5b\x83\x43" nocase
    $wide = "\x30d7\x00\x30ec\x00\x30a4\x00\x30dc\x00\x30fc\x00\x30a4\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_161 {
  meta:
    info = "ペニスバンド"
  strings:
    $utf8 = "\xe3\x83\x9a\xe3\x83\x8b\xe3\x82\xb9\xe3\x83\x90\xe3\x83\xb3\xe3\x83\x89" nocase
    $sjis = "\x83\x79\x83\x6a\x83\x58\x83\x6f\x83\x93\x83\x68" nocase
    $wide = "\x30da\x00\x30cb\x00\x30b9\x00\x30d0\x00\x30f3\x00\x30c9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_162 {
  meta:
    info = "ボーイズラブ"
  strings:
    $utf8 = "\xe3\x83\x9c\xe3\x83\xbc\xe3\x82\xa4\xe3\x82\xba\xe3\x83\xa9\xe3\x83\x96" nocase
    $sjis = "\x83\x7b\x81\x5b\x83\x43\x83\x59\x83\x89\x83\x75" nocase
    $wide = "\x30dc\x00\x30fc\x00\x30a4\x00\x30ba\x00\x30e9\x00\x30d6\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_163 {
  meta:
    info = "ボールを蹴る"
  strings:
    $utf8 = "\xe3\x83\x9c\xe3\x83\xbc\xe3\x83\xab\xe3\x82\x92\xe8\xb9\xb4\xe3\x82\x8b" nocase
    $sjis = "\x83\x7b\x81\x5b\x83\x8b\x82\xf0\x8f\x52\x82\xe9" nocase
    $wide = "\x30dc\x00\x30fc\x00\x30eb\x00\x3092\x00\x8e74\x00\x308b\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_164 {
  meta:
    info = "ボールギャグ"
  strings:
    $utf8 = "\xe3\x83\x9c\xe3\x83\xbc\xe3\x83\xab\xe3\x82\xae\xe3\x83\xa3\xe3\x82\xb0" nocase
    $sjis = "\x83\x7b\x81\x5b\x83\x8b\x83\x4d\x83\x83\x83\x4f" nocase
    $wide = "\x30dc\x00\x30fc\x00\x30eb\x00\x30ae\x00\x30e3\x00\x30b0\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_165 {
  meta:
    info = "ランジェリー"
  strings:
    $utf8 = "\xe3\x83\xa9\xe3\x83\xb3\xe3\x82\xb8\xe3\x82\xa7\xe3\x83\xaa\xe3\x83\xbc" nocase
    $sjis = "\x83\x89\x83\x93\x83\x57\x83\x46\x83\x8a\x81\x5b" nocase
    $wide = "\x30e9\x00\x30f3\x00\x30b8\x00\x30a7\x00\x30ea\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_166 {
  meta:
    info = "新しいポルノ"
  strings:
    $utf8 = "\xe6\x96\xb0\xe3\x81\x97\xe3\x81\x84\xe3\x83\x9d\xe3\x83\xab\xe3\x83\x8e" nocase
    $sjis = "\x90\x56\x82\xb5\x82\xa2\x83\x7c\x83\x8b\x83\x6d" nocase
    $wide = "\x65b0\x00\x3057\x00\x3044\x00\x30dd\x00\x30eb\x00\x30ce\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_167 {
  meta:
    info = "カーマスートラ"
  strings:
    $utf8 = "\xe3\x82\xab\xe3\x83\xbc\xe3\x83\x9e\xe3\x82\xb9\xe3\x83\xbc\xe3\x83\x88\xe3\x83\xa9" nocase
    $sjis = "\x83\x4a\x81\x5b\x83\x7d\x83\x58\x81\x5b\x83\x67\x83\x89" nocase
    $wide = "\x30ab\x00\x30fc\x00\x30de\x00\x30b9\x00\x30fc\x00\x30c8\x00\x30e9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_168 {
  meta:
    info = "クンニリングス"
  strings:
    $utf8 = "\xe3\x82\xaf\xe3\x83\xb3\xe3\x83\x8b\xe3\x83\xaa\xe3\x83\xb3\xe3\x82\xb0\xe3\x82\xb9" nocase
    $sjis = "\x83\x4e\x83\x93\x83\x6a\x83\x8a\x83\x93\x83\x4f\x83\x58" nocase
    $wide = "\x30af\x00\x30f3\x00\x30cb\x00\x30ea\x00\x30f3\x00\x30b0\x00\x30b9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_169 {
  meta:
    info = "ゲイ・セックス"
  strings:
    $utf8 = "\xe3\x82\xb2\xe3\x82\xa4\xe3\x83\xbb\xe3\x82\xbb\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9" nocase
    $sjis = "\x83\x51\x83\x43\x81\x45\x83\x5a\x83\x62\x83\x4e\x83\x58" nocase
    $wide = "\x30b2\x00\x30a4\x00\x30fb\x00\x30bb\x00\x30c3\x00\x30af\x00\x30b9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_170 {
  meta:
    info = "ストラップオン"
  strings:
    $utf8 = "\xe3\x82\xb9\xe3\x83\x88\xe3\x83\xa9\xe3\x83\x83\xe3\x83\x97\xe3\x82\xaa\xe3\x83\xb3" nocase
    $sjis = "\x83\x58\x83\x67\x83\x89\x83\x62\x83\x76\x83\x49\x83\x93" nocase
    $wide = "\x30b9\x00\x30c8\x00\x30e9\x00\x30c3\x00\x30d7\x00\x30aa\x00\x30f3\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_171 {
  meta:
    info = "ストリップ劇場"
  strings:
    $utf8 = "\xe3\x82\xb9\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83\xe3\x83\x97\xe5\x8a\x87\xe5\xa0\xb4" nocase
    $sjis = "\x83\x58\x83\x67\x83\x8a\x83\x62\x83\x76\x8c\x80\x8f\xea" nocase
    $wide = "\x30b9\x00\x30c8\x00\x30ea\x00\x30c3\x00\x30d7\x00\x5287\x00\x5834\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_172 {
  meta:
    info = "ドッグスタイル"
  strings:
    $utf8 = "\xe3\x83\x89\xe3\x83\x83\xe3\x82\xb0\xe3\x82\xb9\xe3\x82\xbf\xe3\x82\xa4\xe3\x83\xab" nocase
    $sjis = "\x83\x68\x83\x62\x83\x4f\x83\x58\x83\x5e\x83\x43\x83\x8b" nocase
    $wide = "\x30c9\x00\x30c3\x00\x30b0\x00\x30b9\x00\x30bf\x00\x30a4\x00\x30eb\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_173 {
  meta:
    info = "バイブレーター"
  strings:
    $utf8 = "\xe3\x83\x90\xe3\x82\xa4\xe3\x83\x96\xe3\x83\xac\xe3\x83\xbc\xe3\x82\xbf\xe3\x83\xbc" nocase
    $sjis = "\x83\x6f\x83\x43\x83\x75\x83\x8c\x81\x5b\x83\x5e\x81\x5b" nocase
    $wide = "\x30d0\x00\x30a4\x00\x30d6\x00\x30ec\x00\x30fc\x00\x30bf\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_174 {
  meta:
    info = "フェティッシュ"
  strings:
    $utf8 = "\xe3\x83\x95\xe3\x82\xa7\xe3\x83\x86\xe3\x82\xa3\xe3\x83\x83\xe3\x82\xb7\xe3\x83\xa5" nocase
    $sjis = "\x83\x74\x83\x46\x83\x65\x83\x42\x83\x62\x83\x56\x83\x85" nocase
    $wide = "\x30d5\x00\x30a7\x00\x30c6\x00\x30a3\x00\x30c3\x00\x30b7\x00\x30e5\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_175 {
  meta:
    info = "茶色のシャワー"
  strings:
    $utf8 = "\xe8\x8c\xb6\xe8\x89\xb2\xe3\x81\xae\xe3\x82\xb7\xe3\x83\xa3\xe3\x83\xaf\xe3\x83\xbc" nocase
    $sjis = "\x92\x83\x90\x46\x82\xcc\x83\x56\x83\x83\x83\x8f\x81\x5b" nocase
    $wide = "\x8336\x00\x8272\x00\x306e\x00\x30b7\x00\x30e3\x00\x30ef\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_176 {
  meta:
    info = "バック・スタイル"
  strings:
    $utf8 = "\xe3\x83\x90\xe3\x83\x83\xe3\x82\xaf\xe3\x83\xbb\xe3\x82\xb9\xe3\x82\xbf\xe3\x82\xa4\xe3\x83\xab" nocase
    $sjis = "\x83\x6f\x83\x62\x83\x4e\x81\x45\x83\x58\x83\x5e\x83\x43\x83\x8b" nocase
    $wide = "\x30d0\x00\x30c3\x00\x30af\x00\x30fb\x00\x30b9\x00\x30bf\x00\x30a4\x00\x30eb\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_177 {
  meta:
    info = "ポルノグラフィー"
  strings:
    $utf8 = "\xe3\x83\x9d\xe3\x83\xab\xe3\x83\x8e\xe3\x82\xb0\xe3\x83\xa9\xe3\x83\x95\xe3\x82\xa3\xe3\x83\xbc" nocase
    $sjis = "\x83\x7c\x83\x8b\x83\x6d\x83\x4f\x83\x89\x83\x74\x83\x42\x81\x5b" nocase
    $wide = "\x30dd\x00\x30eb\x00\x30ce\x00\x30b0\x00\x30e9\x00\x30d5\x00\x30a3\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_178 {
  meta:
    info = "グループ・セックス"
  strings:
    $utf8 = "\xe3\x82\xb0\xe3\x83\xab\xe3\x83\xbc\xe3\x83\x97\xe3\x83\xbb\xe3\x82\xbb\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9" nocase
    $sjis = "\x83\x4f\x83\x8b\x81\x5b\x83\x76\x81\x45\x83\x5a\x83\x62\x83\x4e\x83\x58" nocase
    $wide = "\x30b0\x00\x30eb\x00\x30fc\x00\x30d7\x00\x30fb\x00\x30bb\x00\x30c3\x00\x30af\x00\x30b9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_179 {
  meta:
    info = "ゴールデンシャワー"
  strings:
    $utf8 = "\xe3\x82\xb4\xe3\x83\xbc\xe3\x83\xab\xe3\x83\x87\xe3\x83\xb3\xe3\x82\xb7\xe3\x83\xa3\xe3\x83\xaf\xe3\x83\xbc" nocase
    $sjis = "\x83\x53\x81\x5b\x83\x8b\x83\x66\x83\x93\x83\x56\x83\x83\x83\x8f\x81\x5b" nocase
    $wide = "\x30b4\x00\x30fc\x00\x30eb\x00\x30c7\x00\x30f3\x00\x30b7\x00\x30e3\x00\x30ef\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_180 {
  meta:
    info = "テレフォンセックス"
  strings:
    $utf8 = "\xe3\x83\x86\xe3\x83\xac\xe3\x83\x95\xe3\x82\xa9\xe3\x83\xb3\xe3\x82\xbb\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9" nocase
    $sjis = "\x83\x65\x83\x8c\x83\x74\x83\x48\x83\x93\x83\x5a\x83\x62\x83\x4e\x83\x58" nocase
    $wide = "\x30c6\x00\x30ec\x00\x30d5\x00\x30a9\x00\x30f3\x00\x30bb\x00\x30c3\x00\x30af\x00\x30b9\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_181 {
  meta:
    info = "ディープ・スロート"
  strings:
    $utf8 = "\xe3\x83\x87\xe3\x82\xa3\xe3\x83\xbc\xe3\x83\x97\xe3\x83\xbb\xe3\x82\xb9\xe3\x83\xad\xe3\x83\xbc\xe3\x83\x88" nocase
    $sjis = "\x83\x66\x83\x42\x81\x5b\x83\x76\x81\x45\x83\x58\x83\x8d\x81\x5b\x83\x67" nocase
    $wide = "\x30c7\x00\x30a3\x00\x30fc\x00\x30d7\x00\x30fb\x00\x30b9\x00\x30ed\x00\x30fc\x00\x30c8\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_182 {
  meta:
    info = "マザー・ファッカー"
  strings:
    $utf8 = "\xe3\x83\x9e\xe3\x82\xb6\xe3\x83\xbc\xe3\x83\xbb\xe3\x83\x95\xe3\x82\xa1\xe3\x83\x83\xe3\x82\xab\xe3\x83\xbc" nocase
    $sjis = "\x83\x7d\x83\x55\x81\x5b\x81\x45\x83\x74\x83\x40\x83\x62\x83\x4a\x81\x5b" nocase
    $wide = "\x30de\x00\x30b6\x00\x30fc\x00\x30fb\x00\x30d5\x00\x30a1\x00\x30c3\x00\x30ab\x00\x30fc\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_183 {
  meta:
    info = "マスターベーション"
  strings:
    $utf8 = "\xe3\x83\x9e\xe3\x82\xb9\xe3\x82\xbf\xe3\x83\xbc\xe3\x83\x99\xe3\x83\xbc\xe3\x82\xb7\xe3\x83\xa7\xe3\x83\xb3" nocase
    $sjis = "\x83\x7d\x83\x58\x83\x5e\x81\x5b\x83\x78\x81\x5b\x83\x56\x83\x87\x83\x93" nocase
    $wide = "\x30de\x00\x30b9\x00\x30bf\x00\x30fc\x00\x30d9\x00\x30fc\x00\x30b7\x00\x30e7\x00\x30f3\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_184 {
  meta:
    info = "アジアのかわいい女の子"
  strings:
    $utf8 = "\xe3\x82\xa2\xe3\x82\xb8\xe3\x82\xa2\xe3\x81\xae\xe3\x81\x8b\xe3\x82\x8f\xe3\x81\x84\xe3\x81\x84\xe5\xa5\xb3\xe3\x81\xae\xe5\xad\x90" nocase
    $sjis = "\x83\x41\x83\x57\x83\x41\x82\xcc\x82\xa9\x82\xed\x82\xa2\x82\xa2\x8f\x97\x82\xcc\x8e\x71" nocase
    $wide = "\x30a2\x00\x30b8\x00\x30a2\x00\x306e\x00\x304b\x00\x308f\x00\x3044\x00\x3044\x00\x5973\x00\x306e\x00\x5b50\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_186 {
  meta:
    info = "ちんこ"
  strings:
    $utf8 = "\xe3\x81\xa1\xe3\x82\x93\xe3\x81\x93" nocase
    $sjis = "\x82\xbf\x82\xf1\x82\xb1" nocase
    $wide = "\x3061\x00\x3093\x00\x3053\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_187 {
  meta:
    info = "まんこ"
  strings:
    $utf8 = "\xe3\x81\xbe\xe3\x82\x93\xe3\x81\x93" nocase
    $sjis = "\x82\xdc\x82\xf1\x82\xb1" nocase
    $wide = "\x307e\x00\x3093\x00\x3053\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_189 {
  meta:
    info = "きんたま"
  strings:
    $utf8 = "\xe3\x81\x8d\xe3\x82\x93\xe3\x81\x9f\xe3\x81\xbe" nocase
    $sjis = "\x82\xab\x82\xf1\x82\xbd\x82\xdc" nocase
    $wide = "\x304d\x00\x3093\x00\x305f\x00\x307e\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_190 {
  meta:
    info = "ヤリマン"
  strings:
    $utf8 = "\xe3\x83\xa4\xe3\x83\xaa\xe3\x83\x9e\xe3\x83\xb3" nocase
    $sjis = "\x83\x84\x83\x8a\x83\x7d\x83\x93" nocase
    $wide = "\x30e4\x00\x30ea\x00\x30de\x00\x30f3\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_191 {
  meta:
    info = "淫乱"
  strings:
    $utf8 = "\xe6\xb7\xab\xe4\xb9\xb1" nocase
    $sjis = "\x88\xfa\x97\x90" nocase
    $wide = "\x6deb\x00\x4e71\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_192 {
  meta:
    info = "痴女"
  strings:
    $utf8 = "\xe7\x97\xb4\xe5\xa5\xb3" nocase
    $sjis = "\x92\x73\x8f\x97" nocase
    $wide = "\x75f4\x00\x5973\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_194 {
  meta:
    info = "中出し"
  strings:
    $utf8 = "\xe4\xb8\xad\xe5\x87\xba\xe3\x81\x97" nocase
    $sjis = "\x92\x86\x8f\x6f\x82\xb5" nocase
    $wide = "\x4e2d\x00\x51fa\x00\x3057\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_196 {
  meta:
    info = "顔射"
  strings:
    $utf8 = "\xe9\xa1\x94\xe5\xb0\x84" nocase
    $sjis = "\x8a\xe7\x8e\xcb" nocase
    $wide = "\x9854\x00\x5c04\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_197 {
  meta:
    info = "パイズリ"
  strings:
    $utf8 = "\xe3\x83\x91\xe3\x82\xa4\xe3\x82\xba\xe3\x83\xaa" nocase
    $sjis = "\x83\x70\x83\x43\x83\x59\x83\x8a" nocase
    $wide = "\x30d1\x00\x30a4\x00\x30ba\x00\x30ea\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_198 {
  meta:
    info = "フェラチオ"
  strings:
    $utf8 = "\xe3\x83\x95\xe3\x82\xa7\xe3\x83\xa9\xe3\x83\x81\xe3\x82\xaa" nocase
    $sjis = "\x83\x74\x83\x46\x83\x89\x83\x60\x83\x49" nocase
    $wide = "\x30d5\x00\x30a7\x00\x30e9\x00\x30c1\x00\x30aa\x00" nocase
  condition:
    any of them
}

rule content_ja_language_nsfw_199 {
  meta:
    info = "クンニ"
  strings:
    $utf8 = "\xe3\x82\xaf\xe3\x83\xb3\xe3\x83\x8b" nocase
    $sjis = "\x83\x4e\x83\x93\x83\x6a" nocase
    $wide = "\x30af\x00\x30f3\x00\x30cb\x00" nocase
  condition:
    any of them
}


