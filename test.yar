rule D_Unix_dot_Trojan_dot_Mirai_dash_7135823_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-7135823-0"
        author         = "ClamAV"
        source         = "ClamAV"
        hash           = "e467f1baebf2bbc565ffeb631e92d344"
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
