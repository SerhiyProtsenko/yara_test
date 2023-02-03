rule Unix_dot_Trojan_dot_IRCAESAgent_dash_1
{
    meta:
        
        title          = "Unix.Trojan.IRCAESAgent-1"
		sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 41654c355a537842706267587663314d6258466853364c464c6f7362315464425839396f616a51724e68773d }
		$a1 = { 57676954687a4f5849357058366d4f357a65574f2b4e6d384b5641574e726b4532326d39636c77496450383d }
		$a2 = { 645a7443367248424975786375782f30464c52412f4b61776a6f724459476a314636416a77302f4c6d5268686a376b7344332b3176796175584e485736776a7a }
		$a3 = { 6165735f64656372797074 }
		$a4 = { E8????0D0083F8000F8411000000 }
		$a5 = { 8901E8??????0083C001890424E8????0D00 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4 and $a5)
}
// --

rule Pdf_Dropper_Agent_8087592
{
    meta:
        
        title          = "Pdf.Dropper.Agent-8087592-0:73"
		hash			 = "c6c2ddd65229a1a29df32cbd5b420e68"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		        $hash = { c6 c2 dd d6 52 29 a1 a2 9d f3 2c bd 5b 42 0e 68 }

    condition:
      filesize == 36086 and hash.md5(0, filesize) == $hash
}
// --
