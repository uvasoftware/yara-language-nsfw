rule content_th_language_nsfw_1 {
  meta:
    info = "กู"
  strings:
    $utf8 = "\xe0\xb8\x81\xe0\xb8\xb9" nocase fullword
    $wide = "\x01\x0e\x39\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_2 {
  meta:
    info = "หี"
  strings:
    $utf8 = "\xe0\xb8\xab\xe0\xb8\xb5" nocase fullword
    $wide = "\x2b\x0e\x35\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_3 {
  meta:
    info = "ขี้"
  strings:
    $utf8 = "\xe0\xb8\x82\xe0\xb8\xb5\xe0\xb9\x89" nocase fullword
    $wide = "\x02\x0e\x35\x0e\x49\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_4 {
  meta:
    info = "ควย"
  strings:
    $utf8 = "\xe0\xb8\x84\xe0\xb8\xa7\xe0\xb8\xa2" nocase fullword
    $wide = "\x04\x0e\x27\x0e\x22\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_5 {
  meta:
    info = "จู๋"
  strings:
    $utf8 = "\xe0\xb8\x88\xe0\xb8\xb9\xe0\xb9\x8b" nocase fullword
    $wide = "\x08\x0e\x39\x0e\x4b\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_6 {
  meta:
    info = "ตูด"
  strings:
    $utf8 = "\xe0\xb8\x95\xe0\xb8\xb9\xe0\xb8\x94" nocase fullword
    $wide = "\x15\x0e\x39\x0e\x14\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_7 {
  meta:
    info = "มึง"
  strings:
    $utf8 = "\xe0\xb8\xa1\xe0\xb8\xb6\xe0\xb8\x87" nocase fullword
    $wide = "\x21\x0e\x36\x0e\x07\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_8 {
  meta:
    info = "สัด"
  strings:
    $utf8 = "\xe0\xb8\xaa\xe0\xb8\xb1\xe0\xb8\x94" nocase fullword
    $wide = "\x2a\x0e\x31\x0e\x14\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_9 {
  meta:
    info = "ห่า"
  strings:
    $utf8 = "\xe0\xb8\xab\xe0\xb9\x88\xe0\xb8\xb2" nocase fullword
    $wide = "\x2b\x0e\x48\x0e\x32\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_10 {
  meta:
    info = "หํา"
  strings:
    $utf8 = "\xe0\xb8\xab\xe0\xb9\x8d\xe0\xb8\xb2" nocase fullword
    $wide = "\x2b\x0e\x4d\x0e\x32\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_11 {
  meta:
    info = "กะปิ"
  strings:
    $utf8 = "\xe0\xb8\x81\xe0\xb8\xb0\xe0\xb8\x9b\xe0\xb8\xb4" nocase fullword
    $wide = "\x01\x0e\x30\x0e\x1b\x0e\x34\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_12 {
  meta:
    info = "จิ๋ม"
  strings:
    $utf8 = "\xe0\xb8\x88\xe0\xb8\xb4\xe0\xb9\x8b\xe0\xb8\xa1" nocase fullword
    $wide = "\x08\x0e\x34\x0e\x4b\x0e\x21\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_13 {
  meta:
    info = "เจ๊ก"
  strings:
    $utf8 = "\xe0\xb9\x80\xe0\xb8\x88\xe0\xb9\x8a\xe0\xb8\x81" nocase fullword
    $wide = "\x40\x0e\x08\x0e\x4a\x0e\x01\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_14 {
  meta:
    info = "เย็ด"
  strings:
    $utf8 = "\xe0\xb9\x80\xe0\xb8\xa2\xe0\xb9\x87\xe0\xb8\x94" nocase fullword
    $wide = "\x40\x0e\x22\x0e\x47\x0e\x14\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_15 {
  meta:
    info = "แม่ง"
  strings:
    $utf8 = "\xe0\xb9\x81\xe0\xb8\xa1\xe0\xb9\x88\xe0\xb8\x87" nocase fullword
    $wide = "\x41\x0e\x21\x0e\x48\x0e\x07\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_16 {
  meta:
    info = "กระดอ"
  strings:
    $utf8 = "\xe0\xb8\x81\xe0\xb8\xa3\xe0\xb8\xb0\xe0\xb8\x94\xe0\xb8\xad" nocase fullword
    $wide = "\x01\x0e\x23\x0e\x30\x0e\x14\x0e\x2d\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_17 {
  meta:
    info = "ตอแหล"
  strings:
    $utf8 = "\xe0\xb8\x95\xe0\xb8\xad\xe0\xb9\x81\xe0\xb8\xab\xe0\xb8\xa5" nocase fullword
    $wide = "\x15\x0e\x2d\x0e\x41\x0e\x2b\x0e\x25\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_18 {
  meta:
    info = "รูตูด"
  strings:
    $utf8 = "\xe0\xb8\xa3\xe0\xb8\xb9\xe0\xb8\x95\xe0\xb8\xb9\xe0\xb8\x94" nocase fullword
    $wide = "\x23\x0e\x39\x0e\x15\x0e\x39\x0e\x14\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_19 {
  meta:
    info = "หลั่ง"
  strings:
    $utf8 = "\xe0\xb8\xab\xe0\xb8\xa5\xe0\xb8\xb1\xe0\xb9\x88\xe0\xb8\x87" nocase fullword
    $wide = "\x2b\x0e\x25\x0e\x31\x0e\x48\x0e\x07\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_20 {
  meta:
    info = "เสือก"
  strings:
    $utf8 = "\xe0\xb9\x80\xe0\xb8\xaa\xe0\xb8\xb7\xe0\xb8\xad\xe0\xb8\x81" nocase fullword
    $wide = "\x40\x0e\x2a\x0e\x37\x0e\x2d\x0e\x01\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_21 {
  meta:
    info = "เหี้ย"
  strings:
    $utf8 = "\xe0\xb9\x80\xe0\xb8\xab\xe0\xb8\xb5\xe0\xb9\x89\xe0\xb8\xa2" nocase fullword
    $wide = "\x40\x0e\x2b\x0e\x35\x0e\x49\x0e\x22\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_22 {
  meta:
    info = "ดอกทอง"
  strings:
    $utf8 = "\xe0\xb8\x94\xe0\xb8\xad\xe0\xb8\x81\xe0\xb8\x97\xe0\xb8\xad\xe0\xb8\x87" nocase fullword
    $wide = "\x14\x0e\x2d\x0e\x01\x0e\x17\x0e\x2d\x0e\x07\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_23 {
  meta:
    info = "ส้นตีน"
  strings:
    $utf8 = "\xe0\xb8\xaa\xe0\xb9\x89\xe0\xb8\x99\xe0\xb8\x95\xe0\xb8\xb5\xe0\xb8\x99" nocase fullword
    $wide = "\x2a\x0e\x49\x0e\x19\x0e\x15\x0e\x35\x0e\x19\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_24 {
  meta:
    info = "เจี๊ยว"
  strings:
    $utf8 = "\xe0\xb9\x80\xe0\xb8\x88\xe0\xb8\xb5\xe0\xb9\x8a\xe0\xb8\xa2\xe0\xb8\xa7" nocase fullword
    $wide = "\x40\x0e\x08\x0e\x35\x0e\x4a\x0e\x22\x0e\x27\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_25 {
  meta:
    info = "กระหรี่"
  strings:
    $utf8 = "\xe0\xb8\x81\xe0\xb8\xa3\xe0\xb8\xb0\xe0\xb8\xab\xe0\xb8\xa3\xe0\xb8\xb5\xe0\xb9\x88" nocase fullword
    $wide = "\x01\x0e\x23\x0e\x30\x0e\x2b\x0e\x23\x0e\x35\x0e\x48\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_26 {
  meta:
    info = "กระเด้า"
  strings:
    $utf8 = "\xe0\xb8\x81\xe0\xb8\xa3\xe0\xb8\xb0\xe0\xb9\x80\xe0\xb8\x94\xe0\xb9\x89\xe0\xb8\xb2" nocase fullword
    $wide = "\x01\x0e\x23\x0e\x30\x0e\x40\x0e\x14\x0e\x49\x0e\x32\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_27 {
  meta:
    info = "น้ําแตก"
  strings:
    $utf8 = "\xe0\xb8\x99\xe0\xb9\x89\xe0\xb9\x8d\xe0\xb8\xb2\xe0\xb9\x81\xe0\xb8\x95\xe0\xb8\x81" nocase fullword
    $wide = "\x19\x0e\x49\x0e\x4d\x0e\x32\x0e\x41\x0e\x15\x0e\x01\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_28 {
  meta:
    info = "อมนกเขา"
  strings:
    $utf8 = "\xe0\xb8\xad\xe0\xb8\xa1\xe0\xb8\x99\xe0\xb8\x81\xe0\xb9\x80\xe0\xb8\x82\xe0\xb8\xb2" nocase fullword
    $wide = "\x2d\x0e\x21\x0e\x19\x0e\x01\x0e\x40\x0e\x02\x0e\x32\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_29 {
  meta:
    info = "ไอ้ควาย"
  strings:
    $utf8 = "\xe0\xb9\x84\xe0\xb8\xad\xe0\xb9\x89\xe0\xb8\x84\xe0\xb8\xa7\xe0\xb8\xb2\xe0\xb8\xa2" nocase fullword
    $wide = "\x44\x0e\x2d\x0e\x49\x0e\x04\x0e\x27\x0e\x32\x0e\x22\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_30 {
  meta:
    info = "ล้างตู้เย็น"
  strings:
    $utf8 = "\xe0\xb8\xa5\xe0\xb9\x89\xe0\xb8\xb2\xe0\xb8\x87\xe0\xb8\x95\xe0\xb8\xb9\xe0\xb9\x89\xe0\xb9\x80\xe0\xb8\xa2\xe0\xb9\x87\xe0\xb8\x99" nocase fullword
    $wide = "\x25\x0e\x49\x0e\x32\x0e\x07\x0e\x15\x0e\x39\x0e\x49\x0e\x40\x0e\x22\x0e\x47\x0e\x19\x0e" nocase fullword
  condition:
    any of them
}
rule content_th_language_nsfw_31 {
  meta:
    info = "หญิงชาติชั่ว"
  strings:
    $utf8 = "\xe0\xb8\xab\xe0\xb8\x8d\xe0\xb8\xb4\xe0\xb8\x87\xe0\xb8\x8a\xe0\xb8\xb2\xe0\xb8\x95\xe0\xb8\xb4\xe0\xb8\x8a\xe0\xb8\xb1\xe0\xb9\x88\xe0\xb8\xa7" nocase fullword
    $wide = "\x2b\x0e\x0d\x0e\x34\x0e\x07\x0e\x0a\x0e\x32\x0e\x15\x0e\x34\x0e\x0a\x0e\x31\x0e\x48\x0e\x27\x0e" nocase fullword
  condition:
    any of them
}
