rule content_ar_language_nsfw {
  strings:
    $s1  =  "سكس"  fullword wide ascii nocase
    $s2  =  "طيز"  fullword wide ascii nocase
    $s3  =  "شرج"  fullword wide ascii nocase
    $s4  =  "لعق"  fullword wide ascii nocase
    $s5  =  "لحس"  fullword wide ascii nocase
    $s6  =  "مص"  fullword wide ascii nocase
    $s7  =  "تمص"  fullword wide ascii nocase
    $s8  =  "بيضان"  fullword wide ascii nocase
    $s9  =  "ثدي"  fullword wide ascii nocase
    $s10  =  "بز"  fullword wide ascii nocase
    $s11  =  "بزاز"  fullword wide ascii nocase
    $s12  =  "حلمة"  fullword wide ascii nocase
    $s13  =  "مفلقسة"  fullword wide ascii nocase
    $s14  =  "بظر"  fullword wide ascii nocase
    $s15  =  "كس"  fullword wide ascii nocase
    $s16  =  "فرج"  fullword wide ascii nocase
    $s17  =  "شهوة"  fullword wide ascii nocase
    $s18  =  "شاذ"  fullword wide ascii nocase
    $s19  =  "مبادل"  fullword wide ascii nocase
    $s20  =  "عاهرة"  fullword wide ascii nocase
    $s21  =  "جماع"  fullword wide ascii nocase
    $s22  =  "قضيب"  fullword wide ascii nocase
    $s23  =  "زب"  fullword wide ascii nocase
    $s24  =  "لوطي"  fullword wide ascii nocase
    $s25  =  "لواط"  fullword wide ascii nocase
    $s26  =  "سحاق"  fullword wide ascii nocase
    $s27  =  "سحاقية"  fullword wide ascii nocase
    $s28  =  "اغتصاب"  fullword wide ascii nocase
    $s29  =  "خنثي"  fullword wide ascii nocase
    $s30  =  "احتلام"  fullword wide ascii nocase
    $s31  =  "نيك"  fullword wide ascii nocase
    $s32  =  "متناك"  fullword wide ascii nocase
    $s33  =  "متناكة"  fullword wide ascii nocase
    $s34  =  "شرموطة"  fullword wide ascii nocase
    $s35  =  "عرص"  fullword wide ascii nocase
    $s36  =  "خول"  fullword wide ascii nocase
    $s37  =  "قحبة"  fullword wide ascii nocase
    $s38  =  "لبوة"  fullword wide ascii nocase  
  condition:
    1 of them
}
