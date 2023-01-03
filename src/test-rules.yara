rule content_en_language_unsafe_test {
	// test rule for content in en language 
  strings:
    $ =  "E78F3BC5-9633-4FF8-9311-148ACC4880DF"  fullword wide ascii nocase
  condition:
    1 of them
}

rule content_de_language_unsafe_test {
	// test rule for content in de language 
  strings:
    $ =  "38555D30-84DD-4A1E-808C-E1B1F6C9915E"  fullword wide ascii nocase
  condition:
    1 of them
}

rule content_fr_language_unsafe_test {
	// test rule for content in fr language 
  strings:
    $ =  "06554638-D821-457B-B5D2-AB40B8A14874"  fullword wide ascii nocase
  condition:
    1 of them
}