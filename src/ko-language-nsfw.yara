rule content_ko_language_nsfw_1 {
  meta:
    info = "씹"
  strings:
    $utf8 = "\xec\x94\xb9" nocase fullword
    $wide = "\x39\xc5" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_2 {
  meta:
    info = "좆"
  strings:
    $utf8 = "\xec\xa2\x86" nocase fullword
    $wide = "\x86\xc8" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_3 {
  meta:
    info = "강간"
  strings:
    $utf8 = "\xea\xb0\x95\xea\xb0\x84" nocase fullword
    $wide = "\x15\xac\x04\xac" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_4 {
  meta:
    info = "개좆"
  strings:
    $utf8 = "\xea\xb0\x9c\xec\xa2\x86" nocase fullword
    $wide = "\x1c\xac\x86\xc8" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_5 {
  meta:
    info = "거유"
  strings:
    $utf8 = "\xea\xb1\xb0\xec\x9c\xa0" nocase fullword
    $wide = "\x70\xac\x20\xc7" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_6 {
  meta:
    info = "고자"
  strings:
    $utf8 = "\xea\xb3\xa0\xec\x9e\x90" nocase fullword
    $wide = "\xe0\xac\x90\xc7" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_7 {
  meta:
    info = "근친"
  strings:
    $utf8 = "\xea\xb7\xbc\xec\xb9\x9c" nocase fullword
    $wide = "\xfc\xad\x5c\xce" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_8 {
  meta:
    info = "노모"
  strings:
    $utf8 = "\xeb\x85\xb8\xeb\xaa\xa8" nocase fullword
    $wide = "\x78\xb1\xa8\xba" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_9 {
  meta:
    info = "때씹"
  strings:
    $utf8 = "\xeb\x95\x8c\xec\x94\xb9" nocase fullword
    $wide = "\x4c\xb5\x39\xc5" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_10 {
  meta:
    info = "뙤놈"
  strings:
    $utf8 = "\xeb\x99\xa4\xeb\x86\x88" nocase fullword
    $wide = "\x64\xb6\x88\xb1" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_11 {
  meta:
    info = "망가"
  strings:
    $utf8 = "\xeb\xa7\x9d\xea\xb0\x80" nocase fullword
    $wide = "\xdd\xb9\x00\xac" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_12 {
  meta:
    info = "몰카"
  strings:
    $utf8 = "\xeb\xaa\xb0\xec\xb9\xb4" nocase fullword
    $wide = "\xb0\xba\x74\xce" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_14 {
  meta:
    info = "변태"
  strings:
    $utf8 = "\xeb\xb3\x80\xed\x83\x9c" nocase fullword
    $wide = "\xc0\xbc\xdc\xd0" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_16 {
  meta:
    info = "보지"
  strings:
    $utf8 = "\xeb\xb3\xb4\xec\xa7\x80" nocase fullword
    $wide = "\xf4\xbc\xc0\xc9" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_17 {
  meta:
    info = "불알"
  strings:
    $utf8 = "\xeb\xb6\x88\xec\x95\x8c" nocase fullword
    $wide = "\x88\xbd\x4c\xc5" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_18 {
  meta:
    info = "섹스"
  strings:
    $utf8 = "\xec\x84\xb9\xec\x8a\xa4" nocase fullword
    $wide = "\x39\xc1\xa4\xc2" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_19 {
  meta:
    info = "쌍놈"
  strings:
    $utf8 = "\xec\x8c\x8d\xeb\x86\x88" nocase fullword
    $wide = "\x0d\xc3\x88\xb1" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_20 {
  meta:
    info = "씨발"
  strings:
    $utf8 = "\xec\x94\xa8\xeb\xb0\x9c" nocase fullword
    $wide = "\x28\xc5\x1c\xbc" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_21 {
  meta:
    info = "씨팔"
  strings:
    $utf8 = "\xec\x94\xa8\xed\x8c\x94" nocase fullword
    $wide = "\x28\xc5\x14\xd3" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_22 {
  meta:
    info = "씹물"
  strings:
    $utf8 = "\xec\x94\xb9\xeb\xac\xbc" nocase fullword
    $wide = "\x39\xc5\x3c\xbb" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_23 {
  meta:
    info = "씹빨"
  strings:
    $utf8 = "\xec\x94\xb9\xeb\xb9\xa8" nocase fullword
    $wide = "\x39\xc5\x68\xbe" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_24 {
  meta:
    info = "씹알"
  strings:
    $utf8 = "\xec\x94\xb9\xec\x95\x8c" nocase fullword
    $wide = "\x39\xc5\x4c\xc5" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_25 {
  meta:
    info = "씹창"
  strings:
    $utf8 = "\xec\x94\xb9\xec\xb0\xbd" nocase fullword
    $wide = "\x39\xc5\x3d\xcc" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_26 {
  meta:
    info = "씹팔"
  strings:
    $utf8 = "\xec\x94\xb9\xed\x8c\x94" nocase fullword
    $wide = "\x39\xc5\x14\xd3" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_27 {
  meta:
    info = "암캐"
  strings:
    $utf8 = "\xec\x95\x94\xec\xba\x90" nocase fullword
    $wide = "\x54\xc5\x90\xce" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_28 {
  meta:
    info = "애자"
  strings:
    $utf8 = "\xec\x95\xa0\xec\x9e\x90" nocase fullword
    $wide = "\x60\xc5\x90\xc7" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_29 {
  meta:
    info = "야동"
  strings:
    $utf8 = "\xec\x95\xbc\xeb\x8f\x99" nocase fullword
    $wide = "\x7c\xc5\xd9\xb3" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_30 {
  meta:
    info = "야사"
  strings:
    $utf8 = "\xec\x95\xbc\xec\x82\xac" nocase fullword
    $wide = "\x7c\xc5\xac\xc0" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_31 {
  meta:
    info = "엄창"
  strings:
    $utf8 = "\xec\x97\x84\xec\xb0\xbd" nocase fullword
    $wide = "\xc4\xc5\x3d\xcc" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_33 {
  meta:
    info = "염병"
  strings:
    $utf8 = "\xec\x97\xbc\xeb\xb3\x91" nocase fullword
    $wide = "\xfc\xc5\xd1\xbc" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_34 {
  meta:
    info = "옘병"
  strings:
    $utf8 = "\xec\x98\x98\xeb\xb3\x91" nocase fullword
    $wide = "\x18\xc6\xd1\xbc" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_35 {
  meta:
    info = "유모"
  strings:
    $utf8 = "\xec\x9c\xa0\xeb\xaa\xa8" nocase fullword
    $wide = "\x20\xc7\xa8\xba" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_36 {
  meta:
    info = "육갑"
  strings:
    $utf8 = "\xec\x9c\xa1\xea\xb0\x91" nocase fullword
    $wide = "\x21\xc7\x11\xac" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_37 {
  meta:
    info = "은꼴"
  strings:
    $utf8 = "\xec\x9d\x80\xea\xbc\xb4" nocase fullword
    $wide = "\x40\xc7\x34\xaf" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_38 {
  meta:
    info = "자위"
  strings:
    $utf8 = "\xec\x9e\x90\xec\x9c\x84" nocase fullword
    $wide = "\x90\xc7\x04\xc7" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_39 {
  meta:
    info = "자지"
  strings:
    $utf8 = "\xec\x9e\x90\xec\xa7\x80" nocase fullword
    $wide = "\x90\xc7\xc0\xc9" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_40 {
  meta:
    info = "잡년"
  strings:
    $utf8 = "\xec\x9e\xa1\xeb\x85\x84" nocase fullword
    $wide = "\xa1\xc7\x44\xb1" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_41 {
  meta:
    info = "좆만"
  strings:
    $utf8 = "\xec\xa2\x86\xeb\xa7\x8c" nocase fullword
    $wide = "\x86\xc8\xcc\xb9" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_42 {
  meta:
    info = "쥐좆"
  strings:
    $utf8 = "\xec\xa5\x90\xec\xa2\x86" nocase fullword
    $wide = "\x50\xc9\x86\xc8" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_43 {
  meta:
    info = "직촬"
  strings:
    $utf8 = "\xec\xa7\x81\xec\xb4\xac" nocase fullword
    $wide = "\xc1\xc9\x2c\xcd" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_44 {
  meta:
    info = "짱깨"
  strings:
    $utf8 = "\xec\xa7\xb1\xea\xb9\xa8" nocase fullword
    $wide = "\xf1\xc9\x68\xae" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_45 {
  meta:
    info = "창녀"
  strings:
    $utf8 = "\xec\xb0\xbd\xeb\x85\x80" nocase fullword
    $wide = "\x3d\xcc\x40\xb1" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_46 {
  meta:
    info = "호로"
  strings:
    $utf8 = "\xed\x98\xb8\xeb\xa1\x9c" nocase fullword
    $wide = "\x38\xd6\x5c\xb8" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_47 {
  meta:
    info = "후장"
  strings:
    $utf8 = "\xed\x9b\x84\xec\x9e\xa5" nocase fullword
    $wide = "\xc4\xd6\xa5\xc7" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_48 {
  meta:
    info = "개새끼"
  strings:
    $utf8 = "\xea\xb0\x9c\xec\x83\x88\xeb\x81\xbc" nocase fullword
    $wide = "\x1c\xac\xc8\xc0\x7c\xb0" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_49 {
  meta:
    info = "개자식"
  strings:
    $utf8 = "\xea\xb0\x9c\xec\x9e\x90\xec\x8b\x9d" nocase fullword
    $wide = "\x1c\xac\x90\xc7\xdd\xc2" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_50 {
  meta:
    info = "개차반"
  strings:
    $utf8 = "\xea\xb0\x9c\xec\xb0\xa8\xeb\xb0\x98" nocase fullword
    $wide = "\x1c\xac\x28\xcc\x18\xbc" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_51 {
  meta:
    info = "계집년"
  strings:
    $utf8 = "\xea\xb3\x84\xec\xa7\x91\xeb\x85\x84" nocase fullword
    $wide = "\xc4\xac\xd1\xc9\x44\xb1" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_52 {
  meta:
    info = "니기미"
  strings:
    $utf8 = "\xeb\x8b\x88\xea\xb8\xb0\xeb\xaf\xb8" nocase fullword
    $wide = "\xc8\xb2\x30\xae\xf8\xbb" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_53 {
  meta:
    info = "뒤질래"
  strings:
    $utf8 = "\xeb\x92\xa4\xec\xa7\x88\xeb\x9e\x98" nocase fullword
    $wide = "\xa4\xb4\xc8\xc9\x98\xb7" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_54 {
  meta:
    info = "딸딸이"
  strings:
    $utf8 = "\xeb\x94\xb8\xeb\x94\xb8\xec\x9d\xb4" nocase fullword
    $wide = "\x38\xb5\x38\xb5\x74\xc7" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_55 {
  meta:
    info = "또라이"
  strings:
    $utf8 = "\xeb\x98\x90\xeb\x9d\xbc\xec\x9d\xb4" nocase fullword
    $wide = "\x10\xb6\x7c\xb7\x74\xc7" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_56 {
  meta:
    info = "로리타"
  strings:
    $utf8 = "\xeb\xa1\x9c\xeb\xa6\xac\xed\x83\x80" nocase fullword
    $wide = "\x5c\xb8\xac\xb9\xc0\xd0" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_57 {
  meta:
    info = "빠구리"
  strings:
    $utf8 = "\xeb\xb9\xa0\xea\xb5\xac\xeb\xa6\xac" nocase fullword
    $wide = "\x60\xbe\x6c\xad\xac\xb9" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_58 {
  meta:
    info = "사까시"
  strings:
    $utf8 = "\xec\x82\xac\xea\xb9\x8c\xec\x8b\x9c" nocase fullword
    $wide = "\xac\xc0\x4c\xae\xdc\xc2" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_59 {
  meta:
    info = "스와핑"
  strings:
    $utf8 = "\xec\x8a\xa4\xec\x99\x80\xed\x95\x91" nocase fullword
    $wide = "\xa4\xc2\x40\xc6\x51\xd5" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_60 {
  meta:
    info = "씨발놈"
  strings:
    $utf8 = "\xec\x94\xa8\xeb\xb0\x9c\xeb\x86\x88" nocase fullword
    $wide = "\x28\xc5\x1c\xbc\x88\xb1" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_61 {
  meta:
    info = "씹새끼"
  strings:
    $utf8 = "\xec\x94\xb9\xec\x83\x88\xeb\x81\xbc" nocase fullword
    $wide = "\x39\xc5\xc8\xc0\x7c\xb0" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_62 {
  meta:
    info = "야애니"
  strings:
    $utf8 = "\xec\x95\xbc\xec\x95\xa0\xeb\x8b\x88" nocase fullword
    $wide = "\x7c\xc5\x60\xc5\xc8\xb2" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_63 {
  meta:
    info = "종간나"
  strings:
    $utf8 = "\xec\xa2\x85\xea\xb0\x84\xeb\x82\x98" nocase fullword
    $wide = "\x85\xc8\x04\xac\x98\xb0" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_64 {
  meta:
    info = "죽일년"
  strings:
    $utf8 = "\xec\xa3\xbd\xec\x9d\xbc\xeb\x85\x84" nocase fullword
    $wide = "\xfd\xc8\x7c\xc7\x44\xb1" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_65 {
  meta:
    info = "쪽바리"
  strings:
    $utf8 = "\xec\xaa\xbd\xeb\xb0\x94\xeb\xa6\xac" nocase fullword
    $wide = "\xbd\xca\x14\xbc\xac\xb9" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_66 {
  meta:
    info = "포르노"
  strings:
    $utf8 = "\xed\x8f\xac\xeb\xa5\xb4\xeb\x85\xb8" nocase fullword
    $wide = "\xec\xd3\x74\xb9\x78\xb1" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_67 {
  meta:
    info = "화냥년"
  strings:
    $utf8 = "\xed\x99\x94\xeb\x83\xa5\xeb\x85\x84" nocase fullword
    $wide = "\x54\xd6\xe5\xb0\x44\xb1" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_68 {
  meta:
    info = "미친새끼"
  strings:
    $utf8 = "\xeb\xaf\xb8\xec\xb9\x9c\xec\x83\x88\xeb\x81\xbc" nocase fullword
    $wide = "\xf8\xbb\x5c\xce\xc8\xc0\x7c\xb0" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_69 {
  meta:
    info = "바바리맨"
  strings:
    $utf8 = "\xeb\xb0\x94\xeb\xb0\x94\xeb\xa6\xac\xeb\xa7\xa8" nocase fullword
    $wide = "\x14\xbc\x14\xbc\xac\xb9\xe8\xb9" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_70 {
  meta:
    info = "하드코어"
  strings:
    $utf8 = "\xed\x95\x98\xeb\x93\x9c\xec\xbd\x94\xec\x96\xb4" nocase fullword
    $wide = "\x58\xd5\xdc\xb4\x54\xcf\xb4\xc5" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_71 {
  meta:
    info = "후레아들"
  strings:
    $utf8 = "\xed\x9b\x84\xeb\xa0\x88\xec\x95\x84\xeb\x93\xa4" nocase fullword
    $wide = "\xc4\xd6\x08\xb8\x44\xc5\xe4\xb4" nocase fullword
  condition:
    any of them
}
rule content_ko_language_nsfw_72 {
  meta:
    info = "희쭈그리"
  strings:
    $utf8 = "\xed\x9d\xac\xec\xad\x88\xea\xb7\xb8\xeb\xa6\xac" nocase fullword
    $wide = "\x6c\xd7\x48\xcb\xf8\xad\xac\xb9" nocase fullword
  condition:
    any of them
}
