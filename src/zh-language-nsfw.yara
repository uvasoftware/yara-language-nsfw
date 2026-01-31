
rule content_zh_language_nsfw_1 {
  meta:
    info = "13点"
  strings:
    $utf8 = "\x31\x33\xe7\x82\xb9" nocase
    $gbk = "\x31\x33\xb5\xe3" nocase
    $wide = "\x31\x00\x33\x00\x70b9\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_5 {
  meta:
    info = "奸"
  strings:
    $utf8 = "\xe5\xa5\xb8" nocase
    $gbk = "\xbc\xe9" nocase
    $wide = "\x5978\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_6 {
  meta:
    info = "妓"
  strings:
    $utf8 = "\xe5\xa6\x93" nocase
    $gbk = "\xbc\xcb" nocase
    $wide = "\x5993\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_7 {
  meta:
    info = "姦"
  strings:
    $utf8 = "\xe5\xa7\xa6" nocase
    $gbk = "\x8a\xa6" nocase
    $wide = "\x59e6\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_8 {
  meta:
    info = "屄"
  strings:
    $utf8 = "\xe5\xb1\x84" nocase
    $gbk = "\x8c\xc2" nocase
    $wide = "\x5c44\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_9 {
  meta:
    info = "屌"
  strings:
    $utf8 = "\xe5\xb1\x8c" nocase
    $gbk = "\x8c\xc5" nocase
    $wide = "\x5c4c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_10 {
  meta:
    info = "幹"
  strings:
    $utf8 = "\xe5\xb9\xb9" nocase
    $gbk = "\x8e\xd6" nocase
    $wide = "\x5e79\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_12 {
  meta:
    info = "淫"
  strings:
    $utf8 = "\xe6\xb7\xab" nocase
    $gbk = "\xd2\xf9" nocase
    $wide = "\x6deb\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_13 {
  meta:
    info = "爛"
  strings:
    $utf8 = "\xe7\x88\x9b" nocase
    $gbk = "\xa0\x80" nocase
    $wide = "\x721b\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_14 {
  meta:
    info = "肏"
  strings:
    $utf8 = "\xe8\x82\x8f" nocase
    $gbk = "\xc3\x48" nocase
    $wide = "\x808f\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_15 {
  meta:
    info = "賤"
  strings:
    $utf8 = "\xe8\xb3\xa4" nocase
    $gbk = "\xd9\x76" nocase
    $wide = "\x8ce4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_16 {
  meta:
    info = "逼"
  strings:
    $utf8 = "\xe9\x80\xbc" nocase
    $gbk = "\xb1\xc6" nocase
    $wide = "\x903c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_17 {
  meta:
    info = "懒8"
  strings:
    $utf8 = "\xe6\x87\x92\x38" nocase
    $gbk = "\xc0\xc1\x38" nocase
    $wide = "\x61d2\x00\x38\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_18 {
  meta:
    info = "鸡8"
  strings:
    $utf8 = "\xe9\xb8\xa1\x38" nocase
    $gbk = "\xbc\xa6\x38" nocase
    $wide = "\x9e21\x00\x38\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_19 {
  meta:
    info = "卖B"
  strings:
    $utf8 = "\xe5\x8d\x96\x42" nocase
    $gbk = "\xc2\xf4\x42" nocase
    $wide = "\x5356\x00\x42\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_20 {
  meta:
    info = "妈B"
  strings:
    $utf8 = "\xe5\xa6\x88\x42" nocase
    $gbk = "\xc2\xe8\x42" nocase
    $wide = "\x5988\x00\x42\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_21 {
  meta:
    info = "贱B"
  strings:
    $utf8 = "\xe8\xb4\xb1\x42" nocase
    $gbk = "\xbc\xfa\x42" nocase
    $wide = "\x8d31\x00\x42\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_22 {
  meta:
    info = "干x娘"
  strings:
    $utf8 = "\xe5\xb9\xb2\x78\xe5\xa8\x98" nocase
    $gbk = "\xb8\xc9\x78\xc4\xef" nocase
    $wide = "\x5e72\x00\x78\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_23 {
  meta:
    info = "下贱"
  strings:
    $utf8 = "\xe4\xb8\x8b\xe8\xb4\xb1" nocase
    $gbk = "\xcf\xc2\xbc\xfa" nocase
    $wide = "\x4e0b\x00\x8d31\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_24 {
  meta:
    info = "九游"
  strings:
    $utf8 = "\xe4\xb9\x9d\xe6\xb8\xb8" nocase
    $gbk = "\xbe\xc5\xd3\xce" nocase
    $wide = "\x4e5d\x00\x6e38\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_25 {
  meta:
    info = "乳交"
  strings:
    $utf8 = "\xe4\xb9\xb3\xe4\xba\xa4" nocase
    $gbk = "\xc8\xe9\xbd\xbb" nocase
    $wide = "\x4e73\x00\x4ea4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_26 {
  meta:
    info = "乳头"
  strings:
    $utf8 = "\xe4\xb9\xb3\xe5\xa4\xb4" nocase
    $gbk = "\xc8\xe9\xcd\xb7" nocase
    $wide = "\x4e73\x00\x5934\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_27 {
  meta:
    info = "乳房"
  strings:
    $utf8 = "\xe4\xb9\xb3\xe6\x88\xbf" nocase
    $gbk = "\xc8\xe9\xb7\xbf" nocase
    $wide = "\x4e73\x00\x623f\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_28 {
  meta:
    info = "交配"
  strings:
    $utf8 = "\xe4\xba\xa4\xe9\x85\x8d" nocase
    $gbk = "\xbd\xbb\xc5\xe4" nocase
    $wide = "\x4ea4\x00\x914d\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_29 {
  meta:
    info = "仆街"
  strings:
    $utf8 = "\xe4\xbb\x86\xe8\xa1\x97" nocase
    $gbk = "\xc6\xcd\xbd\xd6" nocase
    $wide = "\x4ec6\x00\x8857\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_30 {
  meta:
    info = "他妈"
  strings:
    $utf8 = "\xe4\xbb\x96\xe5\xa6\x88" nocase
    $gbk = "\xcb\xfb\xc2\xe8" nocase
    $wide = "\x4ed6\x00\x5988\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_31 {
  meta:
    info = "他娘"
  strings:
    $utf8 = "\xe4\xbb\x96\xe5\xa8\x98" nocase
    $gbk = "\xcb\xfb\xc4\xef" nocase
    $wide = "\x4ed6\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_32 {
  meta:
    info = "你妈"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe5\xa6\x88" nocase
    $gbk = "\xc4\xe3\xc2\xe8" nocase
    $wide = "\x4f60\x00\x5988\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_33 {
  meta:
    info = "你娘"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe5\xa8\x98" nocase
    $gbk = "\xc4\xe3\xc4\xef" nocase
    $wide = "\x4f60\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_34 {
  meta:
    info = "做爱"
  strings:
    $utf8 = "\xe5\x81\x9a\xe7\x88\xb1" nocase
    $gbk = "\xd7\xf6\xb0\xae" nocase
    $wide = "\x505a\x00\x7231\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_35 {
  meta:
    info = "傻比"
  strings:
    $utf8 = "\xe5\x82\xbb\xe6\xaf\x94" nocase
    $gbk = "\xc9\xb5\xb1\xc8" nocase
    $wide = "\x50bb\x00\x6bd4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_36 {
  meta:
    info = "傻逼"
  strings:
    $utf8 = "\xe5\x82\xbb\xe9\x80\xbc" nocase
    $gbk = "\xc9\xb5\xb1\xc6" nocase
    $wide = "\x50bb\x00\x903c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_37 {
  meta:
    info = "册那"
  strings:
    $utf8 = "\xe5\x86\x8c\xe9\x82\xa3" nocase
    $gbk = "\xb2\xe1\xc4\xc7" nocase
    $wide = "\x518c\x00\x90a3\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_38 {
  meta:
    info = "军妓"
  strings:
    $utf8 = "\xe5\x86\x9b\xe5\xa6\x93" nocase
    $gbk = "\xbe\xfc\xbc\xcb" nocase
    $wide = "\x519b\x00\x5993\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_39 {
  meta:
    info = "几八"
  strings:
    $utf8 = "\xe5\x87\xa0\xe5\x85\xab" nocase
    $gbk = "\xbc\xb8\xb0\xcb" nocase
    $wide = "\x51e0\x00\x516b\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_40 {
  meta:
    info = "几叭"
  strings:
    $utf8 = "\xe5\x87\xa0\xe5\x8f\xad" nocase
    $gbk = "\xbc\xb8\xb0\xc8" nocase
    $wide = "\x51e0\x00\x53ed\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_41 {
  meta:
    info = "几巴"
  strings:
    $utf8 = "\xe5\x87\xa0\xe5\xb7\xb4" nocase
    $gbk = "\xbc\xb8\xb0\xcd" nocase
    $wide = "\x51e0\x00\x5df4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_42 {
  meta:
    info = "几芭"
  strings:
    $utf8 = "\xe5\x87\xa0\xe8\x8a\xad" nocase
    $gbk = "\xbc\xb8\xb0\xc5" nocase
    $wide = "\x51e0\x00\x82ad\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_43 {
  meta:
    info = "刚度"
  strings:
    $utf8 = "\xe5\x88\x9a\xe5\xba\xa6" nocase
    $gbk = "\xb8\xd5\xb6\xc8" nocase
    $wide = "\x521a\x00\x5ea6\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_44 {
  meta:
    info = "包皮"
  strings:
    $utf8 = "\xe5\x8c\x85\xe7\x9a\xae" nocase
    $gbk = "\xb0\xfc\xc6\xa4" nocase
    $wide = "\x5305\x00\x76ae\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_45 {
  meta:
    info = "卖比"
  strings:
    $utf8 = "\xe5\x8d\x96\xe6\xaf\x94" nocase
    $gbk = "\xc2\xf4\xb1\xc8" nocase
    $wide = "\x5356\x00\x6bd4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_46 {
  meta:
    info = "卖淫"
  strings:
    $utf8 = "\xe5\x8d\x96\xe6\xb7\xab" nocase
    $gbk = "\xc2\xf4\xd2\xf9" nocase
    $wide = "\x5356\x00\x6deb\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_48 {
  meta:
    info = "口交"
  strings:
    $utf8 = "\xe5\x8f\xa3\xe4\xba\xa4" nocase
    $gbk = "\xbf\xda\xbd\xbb" nocase
    $wide = "\x53e3\x00\x4ea4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_49 {
  meta:
    info = "口肯"
  strings:
    $utf8 = "\xe5\x8f\xa3\xe8\x82\xaf" nocase
    $gbk = "\xbf\xda\xbf\xcf" nocase
    $wide = "\x53e3\x00\x80af\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_50 {
  meta:
    info = "叫床"
  strings:
    $utf8 = "\xe5\x8f\xab\xe5\xba\x8a" nocase
    $gbk = "\xbd\xd0\xb4\xb2" nocase
    $wide = "\x53eb\x00\x5e8a\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_51 {
  meta:
    info = "吃屎"
  strings:
    $utf8 = "\xe5\x90\x83\xe5\xb1\x8e" nocase
    $gbk = "\xb3\xd4\xca\xba" nocase
    $wide = "\x5403\x00\x5c4e\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_52 {
  meta:
    info = "后庭"
  strings:
    $utf8 = "\xe5\x90\x8e\xe5\xba\xad" nocase
    $gbk = "\xba\xf3\xcd\xa5" nocase
    $wide = "\x540e\x00\x5ead\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_53 {
  meta:
    info = "吹箫"
  strings:
    $utf8 = "\xe5\x90\xb9\xe7\xae\xab" nocase
    $gbk = "\xb4\xb5\xf3\xef" nocase
    $wide = "\x5439\x00\x7bab\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_54 {
  meta:
    info = "处女"
  strings:
    $utf8 = "\xe5\xa4\x84\xe5\xa5\xb3" nocase
    $gbk = "\xb4\xa6\xc5\xae" nocase
    $wide = "\x5904\x00\x5973\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_55 {
  meta:
    info = "外阴"
  strings:
    $utf8 = "\xe5\xa4\x96\xe9\x98\xb4" nocase
    $gbk = "\xcd\xe2\xd2\xf5" nocase
    $wide = "\x5916\x00\x9634\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_56 {
  meta:
    info = "奶子"
  strings:
    $utf8 = "\xe5\xa5\xb6\xe5\xad\x90" nocase
    $gbk = "\xc4\xcc\xd7\xd3" nocase
    $wide = "\x5976\x00\x5b50\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_57 {
  meta:
    info = "奸你"
  strings:
    $utf8 = "\xe5\xa5\xb8\xe4\xbd\xa0" nocase
    $gbk = "\xbc\xe9\xc4\xe3" nocase
    $wide = "\x5978\x00\x4f60\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_58 {
  meta:
    info = "妈比"
  strings:
    $utf8 = "\xe5\xa6\x88\xe6\xaf\x94" nocase
    $gbk = "\xc2\xe8\xb1\xc8" nocase
    $wide = "\x5988\x00\x6bd4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_59 {
  meta:
    info = "妈的"
  strings:
    $utf8 = "\xe5\xa6\x88\xe7\x9a\x84" nocase
    $gbk = "\xc2\xe8\xb5\xc4" nocase
    $wide = "\x5988\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_60 {
  meta:
    info = "妈逼"
  strings:
    $utf8 = "\xe5\xa6\x88\xe9\x80\xbc" nocase
    $gbk = "\xc2\xe8\xb1\xc6" nocase
    $wide = "\x5988\x00\x903c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_61 {
  meta:
    info = "妓女"
  strings:
    $utf8 = "\xe5\xa6\x93\xe5\xa5\xb3" nocase
    $gbk = "\xbc\xcb\xc5\xae" nocase
    $wide = "\x5993\x00\x5973\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_62 {
  meta:
    info = "妓院"
  strings:
    $utf8 = "\xe5\xa6\x93\xe9\x99\xa2" nocase
    $gbk = "\xbc\xcb\xd4\xba" nocase
    $wide = "\x5993\x00\x9662\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_63 {
  meta:
    info = "姘头"
  strings:
    $utf8 = "\xe5\xa7\x98\xe5\xa4\xb4" nocase
    $gbk = "\xe6\xb0\xcd\xb7" nocase
    $wide = "\x59d8\x00\x5934\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_64 {
  meta:
    info = "姣西"
  strings:
    $utf8 = "\xe5\xa7\xa3\xe8\xa5\xbf" nocase
    $gbk = "\xe6\xaf\xce\xf7" nocase
    $wide = "\x59e3\x00\x897f\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_65 {
  meta:
    info = "娘的"
  strings:
    $utf8 = "\xe5\xa8\x98\xe7\x9a\x84" nocase
    $gbk = "\xc4\xef\xb5\xc4" nocase
    $wide = "\x5a18\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_66 {
  meta:
    info = "婊子"
  strings:
    $utf8 = "\xe5\xa9\x8a\xe5\xad\x90" nocase
    $gbk = "\xe6\xbb\xd7\xd3" nocase
    $wide = "\x5a4a\x00\x5b50\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_67 {
  meta:
    info = "嫖娼"
  strings:
    $utf8 = "\xe5\xab\x96\xe5\xa8\xbc" nocase
    $gbk = "\xe6\xce\xe6\xbd" nocase
    $wide = "\x5ad6\x00\x5a3c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_68 {
  meta:
    info = "嫖客"
  strings:
    $utf8 = "\xe5\xab\x96\xe5\xae\xa2" nocase
    $gbk = "\xe6\xce\xbf\xcd" nocase
    $wide = "\x5ad6\x00\x5ba2\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_69 {
  meta:
    info = "密洞"
  strings:
    $utf8 = "\xe5\xaf\x86\xe6\xb4\x9e" nocase
    $gbk = "\xc3\xdc\xb6\xb4" nocase
    $wide = "\x5bc6\x00\x6d1e\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_70 {
  meta:
    info = "射你"
  strings:
    $utf8 = "\xe5\xb0\x84\xe4\xbd\xa0" nocase
    $gbk = "\xc9\xe4\xc4\xe3" nocase
    $wide = "\x5c04\x00\x4f60\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_71 {
  meta:
    info = "射精"
  strings:
    $utf8 = "\xe5\xb0\x84\xe7\xb2\xbe" nocase
    $gbk = "\xc9\xe4\xbe\xab" nocase
    $wide = "\x5c04\x00\x7cbe\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_72 {
  meta:
    info = "屁眼"
  strings:
    $utf8 = "\xe5\xb1\x81\xe7\x9c\xbc" nocase
    $gbk = "\xc6\xa8\xd1\xdb" nocase
    $wide = "\x5c41\x00\x773c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_73 {
  meta:
    info = "屁股"
  strings:
    $utf8 = "\xe5\xb1\x81\xe8\x82\xa1" nocase
    $gbk = "\xc6\xa8\xb9\xc9" nocase
    $wide = "\x5c41\x00\x80a1\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_74 {
  meta:
    info = "巨乳"
  strings:
    $utf8 = "\xe5\xb7\xa8\xe4\xb9\xb3" nocase
    $gbk = "\xbe\xde\xc8\xe9" nocase
    $wide = "\x5de8\x00\x4e73\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_75 {
  meta:
    info = "干你"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe4\xbd\xa0" nocase
    $gbk = "\xb8\xc9\xc4\xe3" nocase
    $wide = "\x5e72\x00\x4f60\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_76 {
  meta:
    info = "强奸"
  strings:
    $utf8 = "\xe5\xbc\xba\xe5\xa5\xb8" nocase
    $gbk = "\xc7\xbf\xbc\xe9" nocase
    $wide = "\x5f3a\x00\x5978\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_77 {
  meta:
    info = "性交"
  strings:
    $utf8 = "\xe6\x80\xa7\xe4\xba\xa4" nocase
    $gbk = "\xd0\xd4\xbd\xbb" nocase
    $wide = "\x6027\x00\x4ea4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_78 {
  meta:
    info = "性器"
  strings:
    $utf8 = "\xe6\x80\xa7\xe5\x99\xa8" nocase
    $gbk = "\xd0\xd4\xc6\xf7" nocase
    $wide = "\x6027\x00\x5668\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_79 {
  meta:
    info = "性爱"
  strings:
    $utf8 = "\xe6\x80\xa7\xe7\x88\xb1" nocase
    $gbk = "\xd0\xd4\xb0\xae" nocase
    $wide = "\x6027\x00\x7231\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_80 {
  meta:
    info = "情色"
  strings:
    $utf8 = "\xe6\x83\x85\xe8\x89\xb2" nocase
    $gbk = "\xc7\xe9\xc9\xab" nocase
    $wide = "\x60c5\x00\x8272\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_81 {
  meta:
    info = "懒八"
  strings:
    $utf8 = "\xe6\x87\x92\xe5\x85\xab" nocase
    $gbk = "\xc0\xc1\xb0\xcb" nocase
    $wide = "\x61d2\x00\x516b\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_82 {
  meta:
    info = "懒叫"
  strings:
    $utf8 = "\xe6\x87\x92\xe5\x8f\xab" nocase
    $gbk = "\xc0\xc1\xbd\xd0" nocase
    $wide = "\x61d2\x00\x53eb\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_83 {
  meta:
    info = "懒教"
  strings:
    $utf8 = "\xe6\x87\x92\xe6\x95\x99" nocase
    $gbk = "\xc0\xc1\xbd\xcc" nocase
    $wide = "\x61d2\x00\x6559\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_85 {
  meta:
    info = "扒光"
  strings:
    $utf8 = "\xe6\x89\x92\xe5\x85\x89" nocase
    $gbk = "\xb0\xc7\xb9\xe2" nocase
    $wide = "\x6252\x00\x5149\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_86 {
  meta:
    info = "打炮"
  strings:
    $utf8 = "\xe6\x89\x93\xe7\x82\xae" nocase
    $gbk = "\xb4\xf2\xc5\xda" nocase
    $wide = "\x6253\x00\x70ae\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_87 {
  meta:
    info = "抽插"
  strings:
    $utf8 = "\xe6\x8a\xbd\xe6\x8f\x92" nocase
    $gbk = "\xb3\xe9\xb2\xe5" nocase
    $wide = "\x62bd\x00\x63d2\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_88 {
  meta:
    info = "招妓"
  strings:
    $utf8 = "\xe6\x8b\x9b\xe5\xa6\x93" nocase
    $gbk = "\xd5\xd0\xbc\xcb" nocase
    $wide = "\x62db\x00\x5993\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_89 {
  meta:
    info = "插你"
  strings:
    $utf8 = "\xe6\x8f\x92\xe4\xbd\xa0" nocase
    $gbk = "\xb2\xe5\xc4\xe3" nocase
    $wide = "\x63d2\x00\x4f60\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_90 {
  meta:
    info = "撒尿"
  strings:
    $utf8 = "\xe6\x92\x92\xe5\xb0\xbf" nocase
    $gbk = "\xc8\xf6\xc4\xf2" nocase
    $wide = "\x6492\x00\x5c3f\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_91 {
  meta:
    info = "操你"
  strings:
    $utf8 = "\xe6\x93\x8d\xe4\xbd\xa0" nocase
    $gbk = "\xb2\xd9\xc4\xe3" nocase
    $wide = "\x64cd\x00\x4f60\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_92 {
  meta:
    info = "操妳"
  strings:
    $utf8 = "\xe6\x93\x8d\xe5\xa6\xb3" nocase
    $gbk = "\xb2\xd9\x8a\x85" nocase
    $wide = "\x64cd\x00\x59b3\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_93 {
  meta:
    info = "操比"
  strings:
    $utf8 = "\xe6\x93\x8d\xe6\xaf\x94" nocase
    $gbk = "\xb2\xd9\xb1\xc8" nocase
    $wide = "\x64cd\x00\x6bd4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_94 {
  meta:
    info = "操逼"
  strings:
    $utf8 = "\xe6\x93\x8d\xe9\x80\xbc" nocase
    $gbk = "\xb2\xd9\xb1\xc6" nocase
    $wide = "\x64cd\x00\x903c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_95 {
  meta:
    info = "放荡"
  strings:
    $utf8 = "\xe6\x94\xbe\xe8\x8d\xa1" nocase
    $gbk = "\xb7\xc5\xb5\xb4" nocase
    $wide = "\x653e\x00\x8361\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_96 {
  meta:
    info = "日你"
  strings:
    $utf8 = "\xe6\x97\xa5\xe4\xbd\xa0" nocase
    $gbk = "\xc8\xd5\xc4\xe3" nocase
    $wide = "\x65e5\x00\x4f60\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_97 {
  meta:
    info = "日批"
  strings:
    $utf8 = "\xe6\x97\xa5\xe6\x89\xb9" nocase
    $gbk = "\xc8\xd5\xc5\xfa" nocase
    $wide = "\x65e5\x00\x6279\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_98 {
  meta:
    info = "月经"
  strings:
    $utf8 = "\xe6\x9c\x88\xe7\xbb\x8f" nocase
    $gbk = "\xd4\xc2\xbe\xad" nocase
    $wide = "\x6708\x00\x7ecf\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_99 {
  meta:
    info = "机八"
  strings:
    $utf8 = "\xe6\x9c\xba\xe5\x85\xab" nocase
    $gbk = "\xbb\xfa\xb0\xcb" nocase
    $wide = "\x673a\x00\x516b\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_100 {
  meta:
    info = "机巴"
  strings:
    $utf8 = "\xe6\x9c\xba\xe5\xb7\xb4" nocase
    $gbk = "\xbb\xfa\xb0\xcd" nocase
    $wide = "\x673a\x00\x5df4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_101 {
  meta:
    info = "杂种"
  strings:
    $utf8 = "\xe6\x9d\x82\xe7\xa7\x8d" nocase
    $gbk = "\xd4\xd3\xd6\xd6" nocase
    $wide = "\x6742\x00\x79cd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_102 {
  meta:
    info = "浪叫"
  strings:
    $utf8 = "\xe6\xb5\xaa\xe5\x8f\xab" nocase
    $gbk = "\xc0\xcb\xbd\xd0" nocase
    $wide = "\x6d6a\x00\x53eb\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_103 {
  meta:
    info = "淫乱"
  strings:
    $utf8 = "\xe6\xb7\xab\xe4\xb9\xb1" nocase
    $gbk = "\xd2\xf9\xc2\xd2" nocase
    $wide = "\x6deb\x00\x4e71\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_104 {
  meta:
    info = "淫妇"
  strings:
    $utf8 = "\xe6\xb7\xab\xe5\xa6\x87" nocase
    $gbk = "\xd2\xf9\xb8\xbe" nocase
    $wide = "\x6deb\x00\x5987\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_105 {
  meta:
    info = "淫棍"
  strings:
    $utf8 = "\xe6\xb7\xab\xe6\xa3\x8d" nocase
    $gbk = "\xd2\xf9\xb9\xf7" nocase
    $wide = "\x6deb\x00\x68cd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_106 {
  meta:
    info = "淫水"
  strings:
    $utf8 = "\xe6\xb7\xab\xe6\xb0\xb4" nocase
    $gbk = "\xd2\xf9\xcb\xae" nocase
    $wide = "\x6deb\x00\x6c34\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_107 {
  meta:
    info = "淫秽"
  strings:
    $utf8 = "\xe6\xb7\xab\xe7\xa7\xbd" nocase
    $gbk = "\xd2\xf9\xbb\xe0" nocase
    $wide = "\x6deb\x00\x79fd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_108 {
  meta:
    info = "淫荡"
  strings:
    $utf8 = "\xe6\xb7\xab\xe8\x8d\xa1" nocase
    $gbk = "\xd2\xf9\xb5\xb4" nocase
    $wide = "\x6deb\x00\x8361\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_109 {
  meta:
    info = "淫西"
  strings:
    $utf8 = "\xe6\xb7\xab\xe8\xa5\xbf" nocase
    $gbk = "\xd2\xf9\xce\xf7" nocase
    $wide = "\x6deb\x00\x897f\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_111 {
  meta:
    info = "烂货"
  strings:
    $utf8 = "\xe7\x83\x82\xe8\xb4\xa7" nocase
    $gbk = "\xc0\xc3\xbb\xf5" nocase
    $wide = "\x70c2\x00\x8d27\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_112 {
  meta:
    info = "烂逼"
  strings:
    $utf8 = "\xe7\x83\x82\xe9\x80\xbc" nocase
    $gbk = "\xc0\xc3\xb1\xc6" nocase
    $wide = "\x70c2\x00\x903c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_113 {
  meta:
    info = "狗屁"
  strings:
    $utf8 = "\xe7\x8b\x97\xe5\xb1\x81" nocase
    $gbk = "\xb9\xb7\xc6\xa8" nocase
    $wide = "\x72d7\x00\x5c41\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_114 {
  meta:
    info = "狗日"
  strings:
    $utf8 = "\xe7\x8b\x97\xe6\x97\xa5" nocase
    $gbk = "\xb9\xb7\xc8\xd5" nocase
    $wide = "\x72d7\x00\x65e5\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_115 {
  meta:
    info = "玉杵"
  strings:
    $utf8 = "\xe7\x8e\x89\xe6\x9d\xb5" nocase
    $gbk = "\xd3\xf1\xe8\xc6" nocase
    $wide = "\x7389\x00\x6775\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_116 {
  meta:
    info = "瓜批"
  strings:
    $utf8 = "\xe7\x93\x9c\xe6\x89\xb9" nocase
    $gbk = "\xb9\xcf\xc5\xfa" nocase
    $wide = "\x74dc\x00\x6279\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_117 {
  meta:
    info = "瘪三"
  strings:
    $utf8 = "\xe7\x98\xaa\xe4\xb8\x89" nocase
    $gbk = "\xb1\xf1\xc8\xfd" nocase
    $wide = "\x762a\x00\x4e09\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_118 {
  meta:
    info = "白烂"
  strings:
    $utf8 = "\xe7\x99\xbd\xe7\x83\x82" nocase
    $gbk = "\xb0\xd7\xc0\xc3" nocase
    $wide = "\x767d\x00\x70c2\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_124 {
  meta:
    info = "精子"
  strings:
    $utf8 = "\xe7\xb2\xbe\xe5\xad\x90" nocase
    $gbk = "\xbe\xab\xd7\xd3" nocase
    $wide = "\x7cbe\x00\x5b50\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_125 {
  meta:
    info = "老二"
  strings:
    $utf8 = "\xe8\x80\x81\xe4\xba\x8c" nocase
    $gbk = "\xc0\xcf\xb6\xfe" nocase
    $wide = "\x8001\x00\x4e8c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_126 {
  meta:
    info = "老味"
  strings:
    $utf8 = "\xe8\x80\x81\xe5\x91\xb3" nocase
    $gbk = "\xc0\xcf\xce\xb6" nocase
    $wide = "\x8001\x00\x5473\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_127 {
  meta:
    info = "老母"
  strings:
    $utf8 = "\xe8\x80\x81\xe6\xaf\x8d" nocase
    $gbk = "\xc0\xcf\xc4\xb8" nocase
    $wide = "\x8001\x00\x6bcd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_128 {
  meta:
    info = "肉壁"
  strings:
    $utf8 = "\xe8\x82\x89\xe5\xa3\x81" nocase
    $gbk = "\xc8\xe2\xb1\xda" nocase
    $wide = "\x8089\x00\x58c1\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_129 {
  meta:
    info = "肉棒"
  strings:
    $utf8 = "\xe8\x82\x89\xe6\xa3\x92" nocase
    $gbk = "\xc8\xe2\xb0\xf4" nocase
    $wide = "\x8089\x00\x68d2\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_130 {
  meta:
    info = "肉缝"
  strings:
    $utf8 = "\xe8\x82\x89\xe7\xbc\x9d" nocase
    $gbk = "\xc8\xe2\xb7\xec" nocase
    $wide = "\x8089\x00\x7f1d\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_131 {
  meta:
    info = "肛交"
  strings:
    $utf8 = "\xe8\x82\x9b\xe4\xba\xa4" nocase
    $gbk = "\xb8\xd8\xbd\xbb" nocase
    $wide = "\x809b\x00\x4ea4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_132 {
  meta:
    info = "肥西"
  strings:
    $utf8 = "\xe8\x82\xa5\xe8\xa5\xbf" nocase
    $gbk = "\xb7\xca\xce\xf7" nocase
    $wide = "\x80a5\x00\x897f\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_133 {
  meta:
    info = "色情"
  strings:
    $utf8 = "\xe8\x89\xb2\xe6\x83\x85" nocase
    $gbk = "\xc9\xab\xc7\xe9" nocase
    $wide = "\x8272\x00\x60c5\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_134 {
  meta:
    info = "花柳"
  strings:
    $utf8 = "\xe8\x8a\xb1\xe6\x9f\xb3" nocase
    $gbk = "\xbb\xa8\xc1\xf8" nocase
    $wide = "\x82b1\x00\x67f3\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_135 {
  meta:
    info = "荡妇"
  strings:
    $utf8 = "\xe8\x8d\xa1\xe5\xa6\x87" nocase
    $gbk = "\xb5\xb4\xb8\xbe" nocase
    $wide = "\x8361\x00\x5987\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_136 {
  meta:
    info = "贝肉"
  strings:
    $utf8 = "\xe8\xb4\x9d\xe8\x82\x89" nocase
    $gbk = "\xb1\xb4\xc8\xe2" nocase
    $wide = "\x8d1d\x00\x8089\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_137 {
  meta:
    info = "贱人"
  strings:
    $utf8 = "\xe8\xb4\xb1\xe4\xba\xba" nocase
    $gbk = "\xbc\xfa\xc8\xcb" nocase
    $wide = "\x8d31\x00\x4eba\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_138 {
  meta:
    info = "贱货"
  strings:
    $utf8 = "\xe8\xb4\xb1\xe8\xb4\xa7" nocase
    $gbk = "\xbc\xfa\xbb\xf5" nocase
    $wide = "\x8d31\x00\x8d27\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_139 {
  meta:
    info = "轮奸"
  strings:
    $utf8 = "\xe8\xbd\xae\xe5\xa5\xb8" nocase
    $gbk = "\xc2\xd6\xbc\xe9" nocase
    $wide = "\x8f6e\x00\x5978\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_140 {
  meta:
    info = "迷药"
  strings:
    $utf8 = "\xe8\xbf\xb7\xe8\x8d\xaf" nocase
    $gbk = "\xc3\xd4\xd2\xa9" nocase
    $wide = "\x8ff7\x00\x836f\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_141 {
  meta:
    info = "逼样"
  strings:
    $utf8 = "\xe9\x80\xbc\xe6\xa0\xb7" nocase
    $gbk = "\xb1\xc6\xd1\xf9" nocase
    $wide = "\x903c\x00\x6837\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_142 {
  meta:
    info = "野鸡"
  strings:
    $utf8 = "\xe9\x87\x8e\xe9\xb8\xa1" nocase
    $gbk = "\xd2\xb0\xbc\xa6" nocase
    $wide = "\x91ce\x00\x9e21\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_143 {
  meta:
    info = "阳具"
  strings:
    $utf8 = "\xe9\x98\xb3\xe5\x85\xb7" nocase
    $gbk = "\xd1\xf4\xbe\xdf" nocase
    $wide = "\x9633\x00\x5177\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_144 {
  meta:
    info = "阳萎"
  strings:
    $utf8 = "\xe9\x98\xb3\xe8\x90\x8e" nocase
    $gbk = "\xd1\xf4\xce\xae" nocase
    $wide = "\x9633\x00\x840e\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_145 {
  meta:
    info = "阴唇"
  strings:
    $utf8 = "\xe9\x98\xb4\xe5\x94\x87" nocase
    $gbk = "\xd2\xf5\xb4\xbd" nocase
    $wide = "\x9634\x00\x5507\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_146 {
  meta:
    info = "阴户"
  strings:
    $utf8 = "\xe9\x98\xb4\xe6\x88\xb7" nocase
    $gbk = "\xd2\xf5\xbb\xa7" nocase
    $wide = "\x9634\x00\x6237\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_147 {
  meta:
    info = "阴核"
  strings:
    $utf8 = "\xe9\x98\xb4\xe6\xa0\xb8" nocase
    $gbk = "\xd2\xf5\xba\xcb" nocase
    $wide = "\x9634\x00\x6838\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_148 {
  meta:
    info = "阴毛"
  strings:
    $utf8 = "\xe9\x98\xb4\xe6\xaf\x9b" nocase
    $gbk = "\xd2\xf5\xc3\xab" nocase
    $wide = "\x9634\x00\x6bdb\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_149 {
  meta:
    info = "阴茎"
  strings:
    $utf8 = "\xe9\x98\xb4\xe8\x8c\x8e" nocase
    $gbk = "\xd2\xf5\xbe\xa5" nocase
    $wide = "\x9634\x00\x830e\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_150 {
  meta:
    info = "阴道"
  strings:
    $utf8 = "\xe9\x98\xb4\xe9\x81\x93" nocase
    $gbk = "\xd2\xf5\xb5\xc0" nocase
    $wide = "\x9634\x00\x9053\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_151 {
  meta:
    info = "阴部"
  strings:
    $utf8 = "\xe9\x98\xb4\xe9\x83\xa8" nocase
    $gbk = "\xd2\xf5\xb2\xbf" nocase
    $wide = "\x9634\x00\x90e8\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_152 {
  meta:
    info = "雞巴"
  strings:
    $utf8 = "\xe9\x9b\x9e\xe5\xb7\xb4" nocase
    $gbk = "\xeb\x75\xb0\xcd" nocase
    $wide = "\x96de\x00\x5df4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_153 {
  meta:
    info = "靠北"
  strings:
    $utf8 = "\xe9\x9d\xa0\xe5\x8c\x97" nocase
    $gbk = "\xbf\xbf\xb1\xb1" nocase
    $wide = "\x9760\x00\x5317\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_154 {
  meta:
    info = "靠母"
  strings:
    $utf8 = "\xe9\x9d\xa0\xe6\xaf\x8d" nocase
    $gbk = "\xbf\xbf\xc4\xb8" nocase
    $wide = "\x9760\x00\x6bcd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_155 {
  meta:
    info = "靠爸"
  strings:
    $utf8 = "\xe9\x9d\xa0\xe7\x88\xb8" nocase
    $gbk = "\xbf\xbf\xb0\xd6" nocase
    $wide = "\x9760\x00\x7238\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_156 {
  meta:
    info = "靠背"
  strings:
    $utf8 = "\xe9\x9d\xa0\xe8\x83\x8c" nocase
    $gbk = "\xbf\xbf\xb1\xb3" nocase
    $wide = "\x9760\x00\x80cc\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_157 {
  meta:
    info = "靠腰"
  strings:
    $utf8 = "\xe9\x9d\xa0\xe8\x85\xb0" nocase
    $gbk = "\xbf\xbf\xd1\xfc" nocase
    $wide = "\x9760\x00\x8170\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_158 {
  meta:
    info = "骚比"
  strings:
    $utf8 = "\xe9\xaa\x9a\xe6\xaf\x94" nocase
    $gbk = "\xc9\xa7\xb1\xc8" nocase
    $wide = "\x9a9a\x00\x6bd4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_159 {
  meta:
    info = "骚货"
  strings:
    $utf8 = "\xe9\xaa\x9a\xe8\xb4\xa7" nocase
    $gbk = "\xc9\xa7\xbb\xf5" nocase
    $wide = "\x9a9a\x00\x8d27\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_160 {
  meta:
    info = "骚逼"
  strings:
    $utf8 = "\xe9\xaa\x9a\xe9\x80\xbc" nocase
    $gbk = "\xc9\xa7\xb1\xc6" nocase
    $wide = "\x9a9a\x00\x903c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_161 {
  meta:
    info = "鬼公"
  strings:
    $utf8 = "\xe9\xac\xbc\xe5\x85\xac" nocase
    $gbk = "\xb9\xed\xb9\xab" nocase
    $wide = "\x9b3c\x00\x516c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_162 {
  meta:
    info = "鸡八"
  strings:
    $utf8 = "\xe9\xb8\xa1\xe5\x85\xab" nocase
    $gbk = "\xbc\xa6\xb0\xcb" nocase
    $wide = "\x9e21\x00\x516b\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_163 {
  meta:
    info = "鸡叭"
  strings:
    $utf8 = "\xe9\xb8\xa1\xe5\x8f\xad" nocase
    $gbk = "\xbc\xa6\xb0\xc8" nocase
    $wide = "\x9e21\x00\x53ed\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_164 {
  meta:
    info = "鸡吧"
  strings:
    $utf8 = "\xe9\xb8\xa1\xe5\x90\xa7" nocase
    $gbk = "\xbc\xa6\xb0\xc9" nocase
    $wide = "\x9e21\x00\x5427\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_165 {
  meta:
    info = "鸡奸"
  strings:
    $utf8 = "\xe9\xb8\xa1\xe5\xa5\xb8" nocase
    $gbk = "\xbc\xa6\xbc\xe9" nocase
    $wide = "\x9e21\x00\x5978\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_166 {
  meta:
    info = "鸡巴"
  strings:
    $utf8 = "\xe9\xb8\xa1\xe5\xb7\xb4" nocase
    $gbk = "\xbc\xa6\xb0\xcd" nocase
    $wide = "\x9e21\x00\x5df4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_167 {
  meta:
    info = "鸡芭"
  strings:
    $utf8 = "\xe9\xb8\xa1\xe8\x8a\xad" nocase
    $gbk = "\xbc\xa6\xb0\xc5" nocase
    $wide = "\x9e21\x00\x82ad\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_168 {
  meta:
    info = "鸡鸡"
  strings:
    $utf8 = "\xe9\xb8\xa1\xe9\xb8\xa1" nocase
    $gbk = "\xbc\xa6\xbc\xa6" nocase
    $wide = "\x9e21\x00\x9e21\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_169 {
  meta:
    info = "龟头"
  strings:
    $utf8 = "\xe9\xbe\x9f\xe5\xa4\xb4" nocase
    $gbk = "\xb9\xea\xcd\xb7" nocase
    $wide = "\x9f9f\x00\x5934\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_170 {
  meta:
    info = "妈个B"
  strings:
    $utf8 = "\xe5\xa6\x88\xe4\xb8\xaa\x42" nocase
    $gbk = "\xc2\xe8\xb8\xf6\x42" nocase
    $wide = "\x5988\x00\x4e2a\x00\x42\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_171 {
  meta:
    info = "妈的B"
  strings:
    $utf8 = "\xe5\xa6\x88\xe7\x9a\x84\x42" nocase
    $gbk = "\xc2\xe8\xb5\xc4\x42" nocase
    $wide = "\x5988\x00\x7684\x00\x42\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_172 {
  meta:
    info = "干死CS"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe6\xad\xbb\x43\x53" nocase
    $gbk = "\xb8\xc9\xcb\xc0\x43\x53" nocase
    $wide = "\x5e72\x00\x6b7b\x00\x43\x00\x53\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_173 {
  meta:
    info = "干死GM"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe6\xad\xbb\x47\x4d" nocase
    $gbk = "\xb8\xc9\xcb\xc0\x47\x4d" nocase
    $wide = "\x5e72\x00\x6b7b\x00\x47\x00\x4d\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_174 {
  meta:
    info = "三级片"
  strings:
    $utf8 = "\xe4\xb8\x89\xe7\xba\xa7\xe7\x89\x87" nocase
    $gbk = "\xc8\xfd\xbc\xb6\xc6\xac" nocase
    $wide = "\x4e09\x00\x7ea7\x00\x7247\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_175 {
  meta:
    info = "下三烂"
  strings:
    $utf8 = "\xe4\xb8\x8b\xe4\xb8\x89\xe7\x83\x82" nocase
    $gbk = "\xcf\xc2\xc8\xfd\xc0\xc3" nocase
    $wide = "\x4e0b\x00\x4e09\x00\x70c2\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_176 {
  meta:
    info = "他奶奶"
  strings:
    $utf8 = "\xe4\xbb\x96\xe5\xa5\xb6\xe5\xa5\xb6" nocase
    $gbk = "\xcb\xfb\xc4\xcc\xc4\xcc" nocase
    $wide = "\x4ed6\x00\x5976\x00\x5976\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_177 {
  meta:
    info = "他妈地"
  strings:
    $utf8 = "\xe4\xbb\x96\xe5\xa6\x88\xe5\x9c\xb0" nocase
    $gbk = "\xcb\xfb\xc2\xe8\xb5\xd8" nocase
    $wide = "\x4ed6\x00\x5988\x00\x5730\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_178 {
  meta:
    info = "他妈的"
  strings:
    $utf8 = "\xe4\xbb\x96\xe5\xa6\x88\xe7\x9a\x84" nocase
    $gbk = "\xcb\xfb\xc2\xe8\xb5\xc4" nocase
    $wide = "\x4ed6\x00\x5988\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_179 {
  meta:
    info = "他马的"
  strings:
    $utf8 = "\xe4\xbb\x96\xe9\xa9\xac\xe7\x9a\x84" nocase
    $gbk = "\xcb\xfb\xc2\xed\xb5\xc4" nocase
    $wide = "\x4ed6\x00\x9a6c\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_180 {
  meta:
    info = "你全家"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe5\x85\xa8\xe5\xae\xb6" nocase
    $gbk = "\xc4\xe3\xc8\xab\xbc\xd2" nocase
    $wide = "\x4f60\x00\x5168\x00\x5bb6\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_181 {
  meta:
    info = "你妈的"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe5\xa6\x88\xe7\x9a\x84" nocase
    $gbk = "\xc4\xe3\xc2\xe8\xb5\xc4" nocase
    $wide = "\x4f60\x00\x5988\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_182 {
  meta:
    info = "你娘咧"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe5\xa8\x98\xe5\x92\xa7" nocase
    $gbk = "\xc4\xe3\xc4\xef\xdf\xd6" nocase
    $wide = "\x4f60\x00\x5a18\x00\x54a7\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_183 {
  meta:
    info = "你是鸡"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe6\x98\xaf\xe9\xb8\xa1" nocase
    $gbk = "\xc4\xe3\xca\xc7\xbc\xa6" nocase
    $wide = "\x4f60\x00\x662f\x00\x9e21\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_184 {
  meta:
    info = "你是鸭"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe6\x98\xaf\xe9\xb8\xad" nocase
    $gbk = "\xc4\xe3\xca\xc7\xd1\xbc" nocase
    $wide = "\x4f60\x00\x662f\x00\x9e2d\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_185 {
  meta:
    info = "你马的"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe9\xa9\xac\xe7\x9a\x84" nocase
    $gbk = "\xc4\xe3\xc2\xed\xb5\xc4" nocase
    $wide = "\x4f60\x00\x9a6c\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_186 {
  meta:
    info = "刚瘪三"
  strings:
    $utf8 = "\xe5\x88\x9a\xe7\x98\xaa\xe4\xb8\x89" nocase
    $gbk = "\xb8\xd5\xb1\xf1\xc8\xfd" nocase
    $wide = "\x521a\x00\x762a\x00\x4e09\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_187 {
  meta:
    info = "十三点"
  strings:
    $utf8 = "\xe5\x8d\x81\xe4\xb8\x89\xe7\x82\xb9" nocase
    $gbk = "\xca\xae\xc8\xfd\xb5\xe3" nocase
    $wide = "\x5341\x00\x4e09\x00\x70b9\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_188 {
  meta:
    info = "塞你公"
  strings:
    $utf8 = "\xe5\xa1\x9e\xe4\xbd\xa0\xe5\x85\xac" nocase
    $gbk = "\xc8\xfb\xc4\xe3\xb9\xab" nocase
    $wide = "\x585e\x00\x4f60\x00\x516c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_189 {
  meta:
    info = "塞你娘"
  strings:
    $utf8 = "\xe5\xa1\x9e\xe4\xbd\xa0\xe5\xa8\x98" nocase
    $gbk = "\xc8\xfb\xc4\xe3\xc4\xef" nocase
    $wide = "\x585e\x00\x4f60\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_190 {
  meta:
    info = "塞你母"
  strings:
    $utf8 = "\xe5\xa1\x9e\xe4\xbd\xa0\xe6\xaf\x8d" nocase
    $gbk = "\xc8\xfb\xc4\xe3\xc4\xb8" nocase
    $wide = "\x585e\x00\x4f60\x00\x6bcd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_191 {
  meta:
    info = "塞你爸"
  strings:
    $utf8 = "\xe5\xa1\x9e\xe4\xbd\xa0\xe7\x88\xb8" nocase
    $gbk = "\xc8\xfb\xc4\xe3\xb0\xd6" nocase
    $wide = "\x585e\x00\x4f60\x00\x7238\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_192 {
  meta:
    info = "大卵子"
  strings:
    $utf8 = "\xe5\xa4\xa7\xe5\x8d\xb5\xe5\xad\x90" nocase
    $gbk = "\xb4\xf3\xc2\xd1\xd7\xd3" nocase
    $wide = "\x5927\x00\x5375\x00\x5b50\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_193 {
  meta:
    info = "大卵泡"
  strings:
    $utf8 = "\xe5\xa4\xa7\xe5\x8d\xb5\xe6\xb3\xa1" nocase
    $gbk = "\xb4\xf3\xc2\xd1\xc5\xdd" nocase
    $wide = "\x5927\x00\x5375\x00\x6ce1\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_194 {
  meta:
    info = "大鸡巴"
  strings:
    $utf8 = "\xe5\xa4\xa7\xe9\xb8\xa1\xe5\xb7\xb4" nocase
    $gbk = "\xb4\xf3\xbc\xa6\xb0\xcd" nocase
    $wide = "\x5927\x00\x9e21\x00\x5df4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_195 {
  meta:
    info = "她妈地"
  strings:
    $utf8 = "\xe5\xa5\xb9\xe5\xa6\x88\xe5\x9c\xb0" nocase
    $gbk = "\xcb\xfd\xc2\xe8\xb5\xd8" nocase
    $wide = "\x5979\x00\x5988\x00\x5730\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_196 {
  meta:
    info = "她妈的"
  strings:
    $utf8 = "\xe5\xa5\xb9\xe5\xa6\x88\xe7\x9a\x84" nocase
    $gbk = "\xcb\xfd\xc2\xe8\xb5\xc4" nocase
    $wide = "\x5979\x00\x5988\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_197 {
  meta:
    info = "她马的"
  strings:
    $utf8 = "\xe5\xa5\xb9\xe9\xa9\xac\xe7\x9a\x84" nocase
    $gbk = "\xcb\xfd\xc2\xed\xb5\xc4" nocase
    $wide = "\x5979\x00\x9a6c\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_198 {
  meta:
    info = "妈个比"
  strings:
    $utf8 = "\xe5\xa6\x88\xe4\xb8\xaa\xe6\xaf\x94" nocase
    $gbk = "\xc2\xe8\xb8\xf6\xb1\xc8" nocase
    $wide = "\x5988\x00\x4e2a\x00\x6bd4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_199 {
  meta:
    info = "妈妈的"
  strings:
    $utf8 = "\xe5\xa6\x88\xe5\xa6\x88\xe7\x9a\x84" nocase
    $gbk = "\xc2\xe8\xc2\xe8\xb5\xc4" nocase
    $wide = "\x5988\x00\x5988\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_200 {
  meta:
    info = "妳妈的"
  strings:
    $utf8 = "\xe5\xa6\xb3\xe5\xa6\x88\xe7\x9a\x84" nocase
    $gbk = "\x8a\x85\xc2\xe8\xb5\xc4" nocase
    $wide = "\x59b3\x00\x5988\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_201 {
  meta:
    info = "妳娘的"
  strings:
    $utf8 = "\xe5\xa6\xb3\xe5\xa8\x98\xe7\x9a\x84" nocase
    $gbk = "\x8a\x85\xc4\xef\xb5\xc4" nocase
    $wide = "\x59b3\x00\x5a18\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_202 {
  meta:
    info = "妳马的"
  strings:
    $utf8 = "\xe5\xa6\xb3\xe9\xa9\xac\xe7\x9a\x84" nocase
    $gbk = "\x8a\x85\xc2\xed\xb5\xc4" nocase
    $wide = "\x59b3\x00\x9a6c\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_203 {
  meta:
    info = "娘个比"
  strings:
    $utf8 = "\xe5\xa8\x98\xe4\xb8\xaa\xe6\xaf\x94" nocase
    $gbk = "\xc4\xef\xb8\xf6\xb1\xc8" nocase
    $wide = "\x5a18\x00\x4e2a\x00\x6bd4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_204 {
  meta:
    info = "它妈地"
  strings:
    $utf8 = "\xe5\xae\x83\xe5\xa6\x88\xe5\x9c\xb0" nocase
    $gbk = "\xcb\xfc\xc2\xe8\xb5\xd8" nocase
    $wide = "\x5b83\x00\x5988\x00\x5730\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_205 {
  meta:
    info = "它妈的"
  strings:
    $utf8 = "\xe5\xae\x83\xe5\xa6\x88\xe7\x9a\x84" nocase
    $gbk = "\xcb\xfc\xc2\xe8\xb5\xc4" nocase
    $wide = "\x5b83\x00\x5988\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_206 {
  meta:
    info = "小乳头"
  strings:
    $utf8 = "\xe5\xb0\x8f\xe4\xb9\xb3\xe5\xa4\xb4" nocase
    $gbk = "\xd0\xa1\xc8\xe9\xcd\xb7" nocase
    $wide = "\x5c0f\x00\x4e73\x00\x5934\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_207 {
  meta:
    info = "小卵子"
  strings:
    $utf8 = "\xe5\xb0\x8f\xe5\x8d\xb5\xe5\xad\x90" nocase
    $gbk = "\xd0\xa1\xc2\xd1\xd7\xd3" nocase
    $wide = "\x5c0f\x00\x5375\x00\x5b50\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_208 {
  meta:
    info = "小卵泡"
  strings:
    $utf8 = "\xe5\xb0\x8f\xe5\x8d\xb5\xe6\xb3\xa1" nocase
    $gbk = "\xd0\xa1\xc2\xd1\xc5\xdd" nocase
    $wide = "\x5c0f\x00\x5375\x00\x6ce1\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_209 {
  meta:
    info = "小瘪三"
  strings:
    $utf8 = "\xe5\xb0\x8f\xe7\x98\xaa\xe4\xb8\x89" nocase
    $gbk = "\xd0\xa1\xb1\xf1\xc8\xfd" nocase
    $wide = "\x5c0f\x00\x762a\x00\x4e09\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_210 {
  meta:
    info = "小肉粒"
  strings:
    $utf8 = "\xe5\xb0\x8f\xe8\x82\x89\xe7\xb2\x92" nocase
    $gbk = "\xd0\xa1\xc8\xe2\xc1\xa3" nocase
    $wide = "\x5c0f\x00\x8089\x00\x7c92\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_211 {
  meta:
    info = "小骚比"
  strings:
    $utf8 = "\xe5\xb0\x8f\xe9\xaa\x9a\xe6\xaf\x94" nocase
    $gbk = "\xd0\xa1\xc9\xa7\xb1\xc8" nocase
    $wide = "\x5c0f\x00\x9a9a\x00\x6bd4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_212 {
  meta:
    info = "小骚货"
  strings:
    $utf8 = "\xe5\xb0\x8f\xe9\xaa\x9a\xe8\xb4\xa7" nocase
    $gbk = "\xd0\xa1\xc9\xa7\xbb\xf5" nocase
    $wide = "\x5c0f\x00\x9a9a\x00\x8d27\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_213 {
  meta:
    info = "小鸡巴"
  strings:
    $utf8 = "\xe5\xb0\x8f\xe9\xb8\xa1\xe5\xb7\xb4" nocase
    $gbk = "\xd0\xa1\xbc\xa6\xb0\xcd" nocase
    $wide = "\x5c0f\x00\x9e21\x00\x5df4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_214 {
  meta:
    info = "小鸡鸡"
  strings:
    $utf8 = "\xe5\xb0\x8f\xe9\xb8\xa1\xe9\xb8\xa1" nocase
    $gbk = "\xd0\xa1\xbc\xa6\xbc\xa6" nocase
    $wide = "\x5c0f\x00\x9e21\x00\x9e21\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_215 {
  meta:
    info = "干七八"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe4\xb8\x83\xe5\x85\xab" nocase
    $gbk = "\xb8\xc9\xc6\xdf\xb0\xcb" nocase
    $wide = "\x5e72\x00\x4e03\x00\x516b\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_216 {
  meta:
    info = "干你妈"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe4\xbd\xa0\xe5\xa6\x88" nocase
    $gbk = "\xb8\xc9\xc4\xe3\xc2\xe8" nocase
    $wide = "\x5e72\x00\x4f60\x00\x5988\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_217 {
  meta:
    info = "干你娘"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe4\xbd\xa0\xe5\xa8\x98" nocase
    $gbk = "\xb8\xc9\xc4\xe3\xc4\xef" nocase
    $wide = "\x5e72\x00\x4f60\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_218 {
  meta:
    info = "干你良"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe4\xbd\xa0\xe8\x89\xaf" nocase
    $gbk = "\xb8\xc9\xc4\xe3\xc1\xbc" nocase
    $wide = "\x5e72\x00\x4f60\x00\x826f\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_219 {
  meta:
    info = "干妳妈"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe5\xa6\xb3\xe5\xa6\x88" nocase
    $gbk = "\xb8\xc9\x8a\x85\xc2\xe8" nocase
    $wide = "\x5e72\x00\x59b3\x00\x5988\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_220 {
  meta:
    info = "干妳娘"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe5\xa6\xb3\xe5\xa8\x98" nocase
    $gbk = "\xb8\xc9\x8a\x85\xc4\xef" nocase
    $wide = "\x5e72\x00\x59b3\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_221 {
  meta:
    info = "干妳马"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe5\xa6\xb3\xe9\xa9\xac" nocase
    $gbk = "\xb8\xc9\x8a\x85\xc2\xed" nocase
    $wide = "\x5e72\x00\x59b3\x00\x9a6c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_222 {
  meta:
    info = "干您娘"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe6\x82\xa8\xe5\xa8\x98" nocase
    $gbk = "\xb8\xc9\xc4\xfa\xc4\xef" nocase
    $wide = "\x5e72\x00\x60a8\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_223 {
  meta:
    info = "干机掰"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe6\x9c\xba\xe6\x8e\xb0" nocase
    $gbk = "\xb8\xc9\xbb\xfa\xea\xfe" nocase
    $wide = "\x5e72\x00\x673a\x00\x63b0\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_224 {
  meta:
    info = "干死你"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe6\xad\xbb\xe4\xbd\xa0" nocase
    $gbk = "\xb8\xc9\xcb\xc0\xc4\xe3" nocase
    $wide = "\x5e72\x00\x6b7b\x00\x4f60\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_225 {
  meta:
    info = "强奸你"
  strings:
    $utf8 = "\xe5\xbc\xba\xe5\xa5\xb8\xe4\xbd\xa0" nocase
    $gbk = "\xc7\xbf\xbc\xe9\xc4\xe3" nocase
    $wide = "\x5f3a\x00\x5978\x00\x4f60\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_226 {
  meta:
    info = "性无能"
  strings:
    $utf8 = "\xe6\x80\xa7\xe6\x97\xa0\xe8\x83\xbd" nocase
    $gbk = "\xd0\xd4\xce\xde\xc4\xdc" nocase
    $wide = "\x6027\x00\x65e0\x00\x80fd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_227 {
  meta:
    info = "想上你"
  strings:
    $utf8 = "\xe6\x83\xb3\xe4\xb8\x8a\xe4\xbd\xa0" nocase
    $gbk = "\xcf\xeb\xc9\xcf\xc4\xe3" nocase
    $wide = "\x60f3\x00\x4e0a\x00\x4f60\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_228 {
  meta:
    info = "懆您妈"
  strings:
    $utf8 = "\xe6\x87\x86\xe6\x82\xa8\xe5\xa6\x88" nocase
    $gbk = "\x91\xa8\xc4\xfa\xc2\xe8" nocase
    $wide = "\x61c6\x00\x60a8\x00\x5988\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_229 {
  meta:
    info = "懆您娘"
  strings:
    $utf8 = "\xe6\x87\x86\xe6\x82\xa8\xe5\xa8\x98" nocase
    $gbk = "\x91\xa8\xc4\xfa\xc4\xef" nocase
    $wide = "\x61c6\x00\x60a8\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_230 {
  meta:
    info = "打飞机"
  strings:
    $utf8 = "\xe6\x89\x93\xe9\xa3\x9e\xe6\x9c\xba" nocase
    $gbk = "\xb4\xf2\xb7\xc9\xbb\xfa" nocase
    $wide = "\x6253\x00\x98de\x00\x673a\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_231 {
  meta:
    info = "插死你"
  strings:
    $utf8 = "\xe6\x8f\x92\xe6\xad\xbb\xe4\xbd\xa0" nocase
    $gbk = "\xb2\xe5\xcb\xc0\xc4\xe3" nocase
    $wide = "\x63d2\x00\x6b7b\x00\x4f60\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_232 {
  meta:
    info = "操你妈"
  strings:
    $utf8 = "\xe6\x93\x8d\xe4\xbd\xa0\xe5\xa6\x88" nocase
    $gbk = "\xb2\xd9\xc4\xe3\xc2\xe8" nocase
    $wide = "\x64cd\x00\x4f60\x00\x5988\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_233 {
  meta:
    info = "操你娘"
  strings:
    $utf8 = "\xe6\x93\x8d\xe4\xbd\xa0\xe5\xa8\x98" nocase
    $gbk = "\xb2\xd9\xc4\xe3\xc4\xef" nocase
    $wide = "\x64cd\x00\x4f60\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_234 {
  meta:
    info = "操妳妈"
  strings:
    $utf8 = "\xe6\x93\x8d\xe5\xa6\xb3\xe5\xa6\x88" nocase
    $gbk = "\xb2\xd9\x8a\x85\xc2\xe8" nocase
    $wide = "\x64cd\x00\x59b3\x00\x5988\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_235 {
  meta:
    info = "操妳娘"
  strings:
    $utf8 = "\xe6\x93\x8d\xe5\xa6\xb3\xe5\xa8\x98" nocase
    $gbk = "\xb2\xd9\x8a\x85\xc4\xef" nocase
    $wide = "\x64cd\x00\x59b3\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_236 {
  meta:
    info = "操机掰"
  strings:
    $utf8 = "\xe6\x93\x8d\xe6\x9c\xba\xe6\x8e\xb0" nocase
    $gbk = "\xb2\xd9\xbb\xfa\xea\xfe" nocase
    $wide = "\x64cd\x00\x673a\x00\x63b0\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_237 {
  meta:
    info = "日他娘"
  strings:
    $utf8 = "\xe6\x97\xa5\xe4\xbb\x96\xe5\xa8\x98" nocase
    $gbk = "\xc8\xd5\xcb\xfb\xc4\xef" nocase
    $wide = "\x65e5\x00\x4ed6\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_238 {
  meta:
    info = "日你妈"
  strings:
    $utf8 = "\xe6\x97\xa5\xe4\xbd\xa0\xe5\xa6\x88" nocase
    $gbk = "\xc8\xd5\xc4\xe3\xc2\xe8" nocase
    $wide = "\x65e5\x00\x4f60\x00\x5988\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_239 {
  meta:
    info = "灨你娘"
  strings:
    $utf8 = "\xe7\x81\xa8\xe4\xbd\xa0\xe5\xa8\x98" nocase
    $gbk = "\x9e\xb8\xc4\xe3\xc4\xef" nocase
    $wide = "\x7068\x00\x4f60\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_240 {
  meta:
    info = "王八蛋"
  strings:
    $utf8 = "\xe7\x8e\x8b\xe5\x85\xab\xe8\x9b\x8b" nocase
    $gbk = "\xcd\xf5\xb0\xcb\xb5\xb0" nocase
    $wide = "\x738b\x00\x516b\x00\x86cb\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_241 {
  meta:
    info = "瓜娃子"
  strings:
    $utf8 = "\xe7\x93\x9c\xe5\xa8\x83\xe5\xad\x90" nocase
    $gbk = "\xb9\xcf\xcd\xde\xd7\xd3" nocase
    $wide = "\x74dc\x00\x5a03\x00\x5b50\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_242 {
  meta:
    info = "瓜婆娘"
  strings:
    $utf8 = "\xe7\x93\x9c\xe5\xa9\x86\xe5\xa8\x98" nocase
    $gbk = "\xb9\xcf\xc6\xc5\xc4\xef" nocase
    $wide = "\x74dc\x00\x5a46\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_243 {
  meta:
    info = "老瘪三"
  strings:
    $utf8 = "\xe8\x80\x81\xe7\x98\xaa\xe4\xb8\x89" nocase
    $gbk = "\xc0\xcf\xb1\xf1\xc8\xfd" nocase
    $wide = "\x8001\x00\x762a\x00\x4e09\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_244 {
  meta:
    info = "老骚比"
  strings:
    $utf8 = "\xe8\x80\x81\xe9\xaa\x9a\xe6\xaf\x94" nocase
    $gbk = "\xc0\xcf\xc9\xa7\xb1\xc8" nocase
    $wide = "\x8001\x00\x9a9a\x00\x6bd4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_245 {
  meta:
    info = "老骚货"
  strings:
    $utf8 = "\xe8\x80\x81\xe9\xaa\x9a\xe8\xb4\xa7" nocase
    $gbk = "\xc0\xcf\xc9\xa7\xbb\xf5" nocase
    $wide = "\x8001\x00\x9a9a\x00\x8d27\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_246 {
  meta:
    info = "肉棍子"
  strings:
    $utf8 = "\xe8\x82\x89\xe6\xa3\x8d\xe5\xad\x90" nocase
    $gbk = "\xc8\xe2\xb9\xf7\xd7\xd3" nocase
    $wide = "\x8089\x00\x68cd\x00\x5b50\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_247 {
  meta:
    info = "贼你妈"
  strings:
    $utf8 = "\xe8\xb4\xbc\xe4\xbd\xa0\xe5\xa6\x88" nocase
    $gbk = "\xd4\xf4\xc4\xe3\xc2\xe8" nocase
    $wide = "\x8d3c\x00\x4f60\x00\x5988\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_248 {
  meta:
    info = "赣您娘"
  strings:
    $utf8 = "\xe8\xb5\xa3\xe6\x82\xa8\xe5\xa8\x98" nocase
    $gbk = "\xb8\xd3\xc4\xfa\xc4\xef" nocase
    $wide = "\x8d63\x00\x60a8\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_249 {
  meta:
    info = "驶你公"
  strings:
    $utf8 = "\xe9\xa9\xb6\xe4\xbd\xa0\xe5\x85\xac" nocase
    $gbk = "\xca\xbb\xc4\xe3\xb9\xab" nocase
    $wide = "\x9a76\x00\x4f60\x00\x516c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_250 {
  meta:
    info = "驶你娘"
  strings:
    $utf8 = "\xe9\xa9\xb6\xe4\xbd\xa0\xe5\xa8\x98" nocase
    $gbk = "\xca\xbb\xc4\xe3\xc4\xef" nocase
    $wide = "\x9a76\x00\x4f60\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_251 {
  meta:
    info = "驶你母"
  strings:
    $utf8 = "\xe9\xa9\xb6\xe4\xbd\xa0\xe6\xaf\x8d" nocase
    $gbk = "\xca\xbb\xc4\xe3\xc4\xb8" nocase
    $wide = "\x9a76\x00\x4f60\x00\x6bcd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_252 {
  meta:
    info = "驶你爸"
  strings:
    $utf8 = "\xe9\xa9\xb6\xe4\xbd\xa0\xe7\x88\xb8" nocase
    $gbk = "\xca\xbb\xc4\xe3\xb0\xd6" nocase
    $wide = "\x9a76\x00\x4f60\x00\x7238\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_253 {
  meta:
    info = "龟儿子"
  strings:
    $utf8 = "\xe9\xbe\x9f\xe5\x84\xbf\xe5\xad\x90" nocase
    $gbk = "\xb9\xea\xb6\xf9\xd7\xd3" nocase
    $wide = "\x9f9f\x00\x513f\x00\x5b50\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_254 {
  meta:
    info = "个老子的"
  strings:
    $utf8 = "\xe4\xb8\xaa\xe8\x80\x81\xe5\xad\x90\xe7\x9a\x84" nocase
    $gbk = "\xb8\xf6\xc0\xcf\xd7\xd3\xb5\xc4" nocase
    $wide = "\x4e2a\x00\x8001\x00\x5b50\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_255 {
  meta:
    info = "乳波臀浪"
  strings:
    $utf8 = "\xe4\xb9\xb3\xe6\xb3\xa2\xe8\x87\x80\xe6\xb5\xaa" nocase
    $gbk = "\xc8\xe9\xb2\xa8\xcd\xce\xc0\xcb" nocase
    $wide = "\x4e73\x00\x6ce2\x00\x81c0\x00\x6d6a\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_256 {
  meta:
    info = "他奶奶的"
  strings:
    $utf8 = "\xe4\xbb\x96\xe5\xa5\xb6\xe5\xa5\xb6\xe7\x9a\x84" nocase
    $gbk = "\xcb\xfb\xc4\xcc\xc4\xcc\xb5\xc4" nocase
    $wide = "\x4ed6\x00\x5976\x00\x5976\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_257 {
  meta:
    info = "他奶娘的"
  strings:
    $utf8 = "\xe4\xbb\x96\xe5\xa5\xb6\xe5\xa8\x98\xe7\x9a\x84" nocase
    $gbk = "\xcb\xfb\xc4\xcc\xc4\xef\xb5\xc4" nocase
    $wide = "\x4ed6\x00\x5976\x00\x5a18\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_258 {
  meta:
    info = "你个傻比"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe4\xb8\xaa\xe5\x82\xbb\xe6\xaf\x94" nocase
    $gbk = "\xc4\xe3\xb8\xf6\xc9\xb5\xb1\xc8" nocase
    $wide = "\x4f60\x00\x4e2a\x00\x50bb\x00\x6bd4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_259 {
  meta:
    info = "你他马的"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe4\xbb\x96\xe9\xa9\xac\xe7\x9a\x84" nocase
    $gbk = "\xc4\xe3\xcb\xfb\xc2\xed\xb5\xc4" nocase
    $wide = "\x4f60\x00\x4ed6\x00\x9a6c\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_260 {
  meta:
    info = "你奶奶的"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe5\xa5\xb6\xe5\xa5\xb6\xe7\x9a\x84" nocase
    $gbk = "\xc4\xe3\xc4\xcc\xc4\xcc\xb5\xc4" nocase
    $wide = "\x4f60\x00\x5976\x00\x5976\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_261 {
  meta:
    info = "你她马的"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe5\xa5\xb9\xe9\xa9\xac\xe7\x9a\x84" nocase
    $gbk = "\xc4\xe3\xcb\xfd\xc2\xed\xb5\xc4" nocase
    $wide = "\x4f60\x00\x5979\x00\x9a6c\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_262 {
  meta:
    info = "你娘卡好"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe5\xa8\x98\xe5\x8d\xa1\xe5\xa5\xbd" nocase
    $gbk = "\xc4\xe3\xc4\xef\xbf\xa8\xba\xc3" nocase
    $wide = "\x4f60\x00\x5a18\x00\x5361\x00\x597d\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_263 {
  meta:
    info = "你它妈的"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe5\xae\x83\xe5\xa6\x88\xe7\x9a\x84" nocase
    $gbk = "\xc4\xe3\xcb\xfc\xc2\xe8\xb5\xc4" nocase
    $wide = "\x4f60\x00\x5b83\x00\x5988\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_264 {
  meta:
    info = "你它马的"
  strings:
    $utf8 = "\xe4\xbd\xa0\xe5\xae\x83\xe9\xa9\xac\xe7\x9a\x84" nocase
    $gbk = "\xc4\xe3\xcb\xfc\xc2\xed\xb5\xc4" nocase
    $wide = "\x4f60\x00\x5b83\x00\x9a6c\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_265 {
  meta:
    info = "双峰微颤"
  strings:
    $utf8 = "\xe5\x8f\x8c\xe5\xb3\xb0\xe5\xbe\xae\xe9\xa2\xa4" nocase
    $gbk = "\xcb\xab\xb7\xe5\xce\xa2\xb2\xfc" nocase
    $wide = "\x53cc\x00\x5cf0\x00\x5fae\x00\x98a4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_266 {
  meta:
    info = "塞你老师"
  strings:
    $utf8 = "\xe5\xa1\x9e\xe4\xbd\xa0\xe8\x80\x81\xe5\xb8\x88" nocase
    $gbk = "\xc8\xfb\xc4\xe3\xc0\xcf\xca\xa6" nocase
    $wide = "\x585e\x00\x4f60\x00\x8001\x00\x5e08\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_267 {
  meta:
    info = "塞你老母"
  strings:
    $utf8 = "\xe5\xa1\x9e\xe4\xbd\xa0\xe8\x80\x81\xe6\xaf\x8d" nocase
    $gbk = "\xc8\xfb\xc4\xe3\xc0\xcf\xc4\xb8" nocase
    $wide = "\x585e\x00\x4f60\x00\x8001\x00\x6bcd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_268 {
  meta:
    info = "奶奶的熊"
  strings:
    $utf8 = "\xe5\xa5\xb6\xe5\xa5\xb6\xe7\x9a\x84\xe7\x86\x8a" nocase
    $gbk = "\xc4\xcc\xc4\xcc\xb5\xc4\xd0\xdc" nocase
    $wide = "\x5976\x00\x5976\x00\x7684\x00\x718a\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_269 {
  meta:
    info = "妈个老比"
  strings:
    $utf8 = "\xe5\xa6\x88\xe4\xb8\xaa\xe8\x80\x81\xe6\xaf\x94" nocase
    $gbk = "\xc2\xe8\xb8\xf6\xc0\xcf\xb1\xc8" nocase
    $wide = "\x5988\x00\x4e2a\x00\x8001\x00\x6bd4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_270 {
  meta:
    info = "妳她妈的"
  strings:
    $utf8 = "\xe5\xa6\xb3\xe5\xa5\xb9\xe5\xa6\x88\xe7\x9a\x84" nocase
    $gbk = "\x8a\x85\xcb\xfd\xc2\xe8\xb5\xc4" nocase
    $wide = "\x59b3\x00\x5979\x00\x5988\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_271 {
  meta:
    info = "妳老母的"
  strings:
    $utf8 = "\xe5\xa6\xb3\xe8\x80\x81\xe6\xaf\x8d\xe7\x9a\x84" nocase
    $gbk = "\x8a\x85\xc0\xcf\xc4\xb8\xb5\xc4" nocase
    $wide = "\x59b3\x00\x8001\x00\x6bcd\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_272 {
  meta:
    info = "婊子养的"
  strings:
    $utf8 = "\xe5\xa9\x8a\xe5\xad\x90\xe5\x85\xbb\xe7\x9a\x84" nocase
    $gbk = "\xe6\xbb\xd7\xd3\xd1\xf8\xb5\xc4" nocase
    $wide = "\x5a4a\x00\x5b50\x00\x517b\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_273 {
  meta:
    info = "干你老母"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe4\xbd\xa0\xe8\x80\x81\xe6\xaf\x8d" nocase
    $gbk = "\xb8\xc9\xc4\xe3\xc0\xcf\xc4\xb8" nocase
    $wide = "\x5e72\x00\x4f60\x00\x8001\x00\x6bcd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_274 {
  meta:
    info = "干妳老母"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe5\xa6\xb3\xe8\x80\x81\xe6\xaf\x8d" nocase
    $gbk = "\xb8\xc9\x8a\x85\xc0\xcf\xc4\xb8" nocase
    $wide = "\x5e72\x00\x59b3\x00\x8001\x00\x6bcd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_275 {
  meta:
    info = "干死客服"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe6\xad\xbb\xe5\xae\xa2\xe6\x9c\x8d" nocase
    $gbk = "\xb8\xc9\xcb\xc0\xbf\xcd\xb7\xfe" nocase
    $wide = "\x5e72\x00\x6b7b\x00\x5ba2\x00\x670d\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_276 {
  meta:
    info = "操你全家"
  strings:
    $utf8 = "\xe6\x93\x8d\xe4\xbd\xa0\xe5\x85\xa8\xe5\xae\xb6" nocase
    $gbk = "\xb2\xd9\xc4\xe3\xc8\xab\xbc\xd2" nocase
    $wide = "\x64cd\x00\x4f60\x00\x5168\x00\x5bb6\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_277 {
  meta:
    info = "操你奶奶"
  strings:
    $utf8 = "\xe6\x93\x8d\xe4\xbd\xa0\xe5\xa5\xb6\xe5\xa5\xb6" nocase
    $gbk = "\xb2\xd9\xc4\xe3\xc4\xcc\xc4\xcc" nocase
    $wide = "\x64cd\x00\x4f60\x00\x5976\x00\x5976\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_278 {
  meta:
    info = "操你祖宗"
  strings:
    $utf8 = "\xe6\x93\x8d\xe4\xbd\xa0\xe7\xa5\x96\xe5\xae\x97" nocase
    $gbk = "\xb2\xd9\xc4\xe3\xd7\xe6\xd7\xda" nocase
    $wide = "\x64cd\x00\x4f60\x00\x7956\x00\x5b97\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_279 {
  meta:
    info = "操你老妈"
  strings:
    $utf8 = "\xe6\x93\x8d\xe4\xbd\xa0\xe8\x80\x81\xe5\xa6\x88" nocase
    $gbk = "\xb2\xd9\xc4\xe3\xc0\xcf\xc2\xe8" nocase
    $wide = "\x64cd\x00\x4f60\x00\x8001\x00\x5988\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_280 {
  meta:
    info = "操你老母"
  strings:
    $utf8 = "\xe6\x93\x8d\xe4\xbd\xa0\xe8\x80\x81\xe6\xaf\x8d" nocase
    $gbk = "\xb2\xd9\xc4\xe3\xc0\xcf\xc4\xb8" nocase
    $wide = "\x64cd\x00\x4f60\x00\x8001\x00\x6bcd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_281 {
  meta:
    info = "操妳全家"
  strings:
    $utf8 = "\xe6\x93\x8d\xe5\xa6\xb3\xe5\x85\xa8\xe5\xae\xb6" nocase
    $gbk = "\xb2\xd9\x8a\x85\xc8\xab\xbc\xd2" nocase
    $wide = "\x64cd\x00\x59b3\x00\x5168\x00\x5bb6\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_282 {
  meta:
    info = "操妳祖宗"
  strings:
    $utf8 = "\xe6\x93\x8d\xe5\xa6\xb3\xe7\xa5\x96\xe5\xae\x97" nocase
    $gbk = "\xb2\xd9\x8a\x85\xd7\xe6\xd7\xda" nocase
    $wide = "\x64cd\x00\x59b3\x00\x7956\x00\x5b97\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_283 {
  meta:
    info = "日你老娘"
  strings:
    $utf8 = "\xe6\x97\xa5\xe4\xbd\xa0\xe8\x80\x81\xe5\xa8\x98" nocase
    $gbk = "\xc8\xd5\xc4\xe3\xc0\xcf\xc4\xef" nocase
    $wide = "\x65e5\x00\x4f60\x00\x8001\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_284 {
  meta:
    info = "日你老母"
  strings:
    $utf8 = "\xe6\x97\xa5\xe4\xbd\xa0\xe8\x80\x81\xe6\xaf\x8d" nocase
    $gbk = "\xc8\xd5\xc4\xe3\xc0\xcf\xc4\xb8" nocase
    $wide = "\x65e5\x00\x4f60\x00\x8001\x00\x6bcd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_285 {
  meta:
    info = "机机歪歪"
  strings:
    $utf8 = "\xe6\x9c\xba\xe6\x9c\xba\xe6\xad\xaa\xe6\xad\xaa" nocase
    $gbk = "\xbb\xfa\xbb\xfa\xcd\xe1\xcd\xe1" nocase
    $wide = "\x673a\x00\x673a\x00\x6b6a\x00\x6b6a\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_286 {
  meta:
    info = "狗狼养的"
  strings:
    $utf8 = "\xe7\x8b\x97\xe7\x8b\xbc\xe5\x85\xbb\xe7\x9a\x84" nocase
    $gbk = "\xb9\xb7\xc0\xc7\xd1\xf8\xb5\xc4" nocase
    $wide = "\x72d7\x00\x72fc\x00\x517b\x00\x7684\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_287 {
  meta:
    info = "赛你老母"
  strings:
    $utf8 = "\xe8\xb5\x9b\xe4\xbd\xa0\xe8\x80\x81\xe6\xaf\x8d" nocase
    $gbk = "\xc8\xfc\xc4\xe3\xc0\xcf\xc4\xb8" nocase
    $wide = "\x8d5b\x00\x4f60\x00\x8001\x00\x6bcd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_288 {
  meta:
    info = "赛妳阿母"
  strings:
    $utf8 = "\xe8\xb5\x9b\xe5\xa6\xb3\xe9\x98\xbf\xe6\xaf\x8d" nocase
    $gbk = "\xc8\xfc\x8a\x85\xb0\xa2\xc4\xb8" nocase
    $wide = "\x8d5b\x00\x59b3\x00\x963f\x00\x6bcd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_289 {
  meta:
    info = "驶你老师"
  strings:
    $utf8 = "\xe9\xa9\xb6\xe4\xbd\xa0\xe8\x80\x81\xe5\xb8\x88" nocase
    $gbk = "\xca\xbb\xc4\xe3\xc0\xcf\xca\xa6" nocase
    $wide = "\x9a76\x00\x4f60\x00\x8001\x00\x5e08\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_290 {
  meta:
    info = "驶你老母"
  strings:
    $utf8 = "\xe9\xa9\xb6\xe4\xbd\xa0\xe8\x80\x81\xe6\xaf\x8d" nocase
    $gbk = "\xca\xbb\xc4\xe3\xc0\xcf\xc4\xb8" nocase
    $wide = "\x9a76\x00\x4f60\x00\x8001\x00\x6bcd\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_291 {
  meta:
    info = "湿透的内裤"
  strings:
    $utf8 = "\xe6\xb9\xbf\xe9\x80\x8f\xe7\x9a\x84\xe5\x86\x85\xe8\xa3\xa4" nocase
    $gbk = "\xca\xaa\xcd\xb8\xb5\xc4\xc4\xda\xbf\xe3" nocase
    $wide = "\x6e7f\x00\x900f\x00\x7684\x00\x5185\x00\x88e4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_292 {
  meta:
    info = "他妈ㄉ王八蛋"
  strings:
    $utf8 = "\xe4\xbb\x96\xe5\xa6\x88\xe3\x84\x89\xe7\x8e\x8b\xe5\x85\xab\xe8\x9b\x8b" nocase
    $gbk = "\xcb\xfb\xc2\xe8\xa8\xc9\xcd\xf5\xb0\xcb\xb5\xb0" nocase
    $wide = "\x4ed6\x00\x5988\x00\x3109\x00\x738b\x00\x516b\x00\x86cb\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_293 {
  meta:
    info = "我操你祖宗十八代"
  strings:
    $utf8 = "\xe6\x88\x91\xe6\x93\x8d\xe4\xbd\xa0\xe7\xa5\x96\xe5\xae\x97\xe5\x8d\x81\xe5\x85\xab\xe4\xbb\xa3" nocase
    $gbk = "\xce\xd2\xb2\xd9\xc4\xe3\xd7\xe6\xd7\xda\xca\xae\xb0\xcb\xb4\xfa" nocase
    $wide = "\x6211\x00\x64cd\x00\x4f60\x00\x7956\x00\x5b97\x00\x5341\x00\x516b\x00\x4ee3\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_294 {
  meta:
    info = "肏"
  strings:
    $utf8 = "\xe8\x82\x8f" nocase
    $gbk = "\xc3\x48" nocase
    $wide = "\x808f\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_295 {
  meta:
    info = "屌"
  strings:
    $utf8 = "\xe5\xb1\x8c" nocase
    $gbk = "\x8c\xc5" nocase
    $wide = "\x5c4c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_296 {
  meta:
    info = "鸡巴"
  strings:
    $utf8 = "\xe9\xb8\xa1\xe5\xb7\xb4" nocase
    $gbk = "\xbc\xa6\xb0\xcd" nocase
    $wide = "\x9e21\x00\x5df4\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_300 {
  meta:
    info = "骚逼"
  strings:
    $utf8 = "\xe9\xaa\x9a\xe9\x80\xbc" nocase
    $gbk = "\xc9\xa7\xb1\xc6" nocase
    $wide = "\x9a9a\x00\x903c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_301 {
  meta:
    info = "臭逼"
  strings:
    $utf8 = "\xe8\x87\xad\xe9\x80\xbc" nocase
    $gbk = "\xb3\xf4\xb1\xc6" nocase
    $wide = "\x81ed\x00\x903c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_302 {
  meta:
    info = "烂逼"
  strings:
    $utf8 = "\xe7\x83\x82\xe9\x80\xbc" nocase
    $gbk = "\xc0\xc3\xb1\xc6" nocase
    $wide = "\x70c2\x00\x903c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_303 {
  meta:
    info = "干你娘"
  strings:
    $utf8 = "\xe5\xb9\xb2\xe4\xbd\xa0\xe5\xa8\x98" nocase
    $gbk = "\xb8\xc9\xc4\xe3\xc4\xef" nocase
    $wide = "\x5e72\x00\x4f60\x00\x5a18\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_304 {
  meta:
    info = "肏你妈"
  strings:
    $utf8 = "\xe8\x82\x8f\xe4\xbd\xa0\xe5\xa6\x88" nocase
    $gbk = "\xc3\x48\xc4\xe3\xc2\xe8" nocase
    $wide = "\x808f\x00\x4f60\x00\x5988\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_305 {
  meta:
    info = "傻逼"
  strings:
    $utf8 = "\xe5\x82\xbb\xe9\x80\xbc" nocase
    $gbk = "\xc9\xb5\xb1\xc6" nocase
    $wide = "\x50bb\x00\x903c\x00" nocase
  condition:
    any of them
}

rule content_zh_language_nsfw_306 {
  meta:
    info = "二逼"
  strings:
    $utf8 = "\xe4\xba\x8c\xe9\x80\xbc" nocase
    $gbk = "\xb6\xfe\xb1\xc6" nocase
    $wide = "\x4e8c\x00\x903c\x00" nocase
  condition:
    any of them
}



