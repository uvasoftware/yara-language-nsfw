rule content_en_language_unsafe_test {
	// test rule for content in en language 
  strings:
    $ =  "ZXCVT/EN"  fullword wide ascii nocase
  condition:
    1 of them
}

rule content_de_language_unsafe_test {
	// test rule for content in de language 
  strings:
    $ =  "ZXCVT/DE"  fullword wide ascii nocase
  condition:
    1 of them
}

rule content_fr_language_unsafe_test {
	// test rule for content in fr language 
  strings:
    $ =  "ZXCVT/FR"  fullword wide ascii nocase
  condition:
    1 of them
}