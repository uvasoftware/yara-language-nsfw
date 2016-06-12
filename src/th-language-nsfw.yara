rule content_th_language_nsfw {
  strings:
      $  =  "กู"  fullword wide ascii nocase
      $  =  "หี"  fullword wide ascii nocase
      $  =  "ขี้"  fullword wide ascii nocase
      $  =  "ควย"  fullword wide ascii nocase
      $  =  "จู๋"  fullword wide ascii nocase
      $  =  "ตูด"  fullword wide ascii nocase
      $  =  "มึง"  fullword wide ascii nocase
      $  =  "สัด"  fullword wide ascii nocase
      $  =  "ห่า"  fullword wide ascii nocase
      $  =  "หํา"  fullword wide ascii nocase
      $  =  "กะปิ"  fullword wide ascii nocase
      $  =  "จิ๋ม"  fullword wide ascii nocase
      $  =  "เจ๊ก"  fullword wide ascii nocase
      $  =  "เย็ด"  fullword wide ascii nocase
      $  =  "แม่ง"  fullword wide ascii nocase
      $  =  "กระดอ"  fullword wide ascii nocase
      $  =  "ตอแหล"  fullword wide ascii nocase
      $  =  "รูตูด"  fullword wide ascii nocase
      $  =  "หลั่ง"  fullword wide ascii nocase
      $  =  "เสือก"  fullword wide ascii nocase
      $  =  "เหี้ย"  fullword wide ascii nocase
      $  =  "ดอกทอง"  fullword wide ascii nocase
      $  =  "ส้นตีน"  fullword wide ascii nocase
      $  =  "เจี๊ยว"  fullword wide ascii nocase
      $  =  "กระหรี่"  fullword wide ascii nocase
      $  =  "กระเด้า"  fullword wide ascii nocase
      $  =  "น้ําแตก"  fullword wide ascii nocase
      $  =  "อมนกเขา"  fullword wide ascii nocase
      $  =  "ไอ้ควาย"  fullword wide ascii nocase
      $  =  "ล้างตู้เย็น"  fullword wide ascii nocase
      $  =  "หญิงชาติชั่ว"  fullword wide ascii nocase
  condition:
    1 of them
}
