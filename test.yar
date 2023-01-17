rule D_Unix_dot_Trojan_dot_Mirai_dash_7135823_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-7135823-0"
        author         = "ClamAV"
        source         = "ClamAV"
	hash	       = "6462b6dfc161555a4361ce42b80b46987c23de0242bc63db7c7ee3f65b494265"	
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 5c595e4b485f }
		$a1 = { 3a703552617d }
		$a2 = { 7351676a7d68324d }
		$a3 = { 584d52514d5c }
		$a4 = { 312852364f266963 }
    condition:
		$a0 and $a1 and $a2 and $a3 and $a4
}

rule D_Unix_dot_Trojan_dot_Mirai_dash_6976991_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-6976991-0"
        author         = "ClamAV"
        source         = "ClamAV"
	hash           = "6ebf26379d458e3d326129619ba57db73f4156eb4ebbc5ed11aeff977c133968"

        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 504f5354202f63646e2d6367692f }
		$a1 = { 4c4756514e4b4c49 }
		$a2 = { 4352524e4756 }
		$a3 = { 5047514d4e54 }
		$a4 = { 4c434f47514750544750 }
    condition:
		$a0 and $a1 and $a2 and $a3 and $a4
}
