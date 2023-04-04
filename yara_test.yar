rule Unix_dot_Exploit_dot_Race_dash_1
{
    meta:
        
        title          = "Unix.Exploit.Race-1"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { e8eef8ffff83c410e84efcffff89c085c0 }
    condition:
		$a0 at manape.sections[13].start + 1413
}

rule Unix_dot_Exploit_dot_Race_dash_2
{
    meta:
        
        title          = "Unix.Exploit.Race-2"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 756964206368616e6765206661696c656400736800657865636c006d6f646966795f6c64740072002f70726f632f736c6162696e666f00 }
    condition:
		$a0
}

rule Unix_dot_Exploit_dot_Small_dash_5347
{
    meta:
        
        title          = "Unix.Exploit.Small-5347"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { e8a103000083fb01c70520ce0a0800000000c70524ce0a0800000000c70528ce0a0800000000c7052cce0a08000000007e08 }
    condition:
		$a0 at manape.sections[2].start + 254
}

rule Unix_dot_Exploit_dot_Local_dash_11
{
    meta:
        
        title          = "Unix.Exploit.Local-11"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 25783a20257320257320257320257320257320257320307825782c25730a004f4b2c20666f756e6420256420746172676574730a0000000000000000000000005b2a5d205374657020342e204578706c6f6974696e6720256420746172676574733a0a0025732f67646200772b0043616e }
    condition:
		$a0
}

rule Unix_dot_Exploit_dot_rpc_dash_1
{
    meta:
        
        title          = "Unix.Exploit.rpc-1"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 41414141256e256e256e256e256e256e256e256e256e }
    condition:
		$a0
}

rule Unix_dot_Trojan_dot_SSHDoor_dash_1
{
    meta:
        
        title          = "Unix.Trojan.SSHDoor-1"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 410fb6041c83c50183f0234188441d0089eb4c89e7e846adfcff4839c372e1488b54240864483314252800000041c6441d00004c89e8750b }
    condition:
		$a0
}

rule Unix_dot_Trojan_dot_Zollard_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Zollard-1"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 557365722d4167656e743a205a6f6c6c617264 }
    condition:
		$a0
}

rule Unix_dot_Trojan_dot_Roopre_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Roopre-1"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 507261676d613a2031333337 }
    condition:
		$a0
}

rule Unix_dot_Trojan_dot_Elknot_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Elknot-1"
        sha256         = "4b33bf74885d5a36c4f549a922b7f18a3ceebb918d97556da20ece5f13c3da91"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 83c40c8d55e483ec0468[2]12088d45e85052 [-] 66616b652e636667 }
    condition:
		$a0
}

rule Unix_dot_Trojan_dot_Starysu_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Starysu-1"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 49414d594f5552474f44 [-] 2e2f6175746f72756e2e73682026 [-] 4743433a2028474e552920342e312e32203230303631313135202870726572656c6561736529202844656269616e20342e312e312d323129 }
    condition:
		$a0
}

rule Unix_dot_Trojan_dot_Starysu_dash_2
{
    meta:
        
        title          = "Unix.Trojan.Starysu-2"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 6675636b794f [-] 2e2f6175746f72756e2e73682026 [-] 4743433a2028474e552920342e312e32203230303631313135202870726572656c6561736529202844656269616e20342e312e312d323129 }
    condition:
		$a0
}

rule Unix_dot_Trojan_dot_Agent_dash_37008
{
    meta:
        
        title          = "Unix.Trojan.Agent-37008"
        sha256         = "9d05b6afbae1ec31ff2d82f1ff9062f7cbfab6346329261a4f19bad4f74d7ee8"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 2f746d702f62696c6c2e6c6f636b [-] 3133435061636b657441747461636b }
    condition:
		$a0
}

rule Unix_dot_Trojan_dot_BDFactory_dash_3
{
    meta:
        
        title          = "Unix.Trojan.BDFactory-3"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 6a39580f054885c0740c48bd[8]ffe5[10-24]0f05 }
    condition:
		$a0 at manape.ep
}

rule Unix_dot_Trojan_dot_BDFactory_dash_4
{
    meta:
        
        title          = "Unix.Trojan.BDFactory-4"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 6a0258cd8085c07407bd[4]ffe5[13]cd80 }
    condition:
		$a0 at manape.ep
}

rule Unix_dot_Trojan_dot_BDFactory_dash_5
{
    meta:
        
        title          = "Unix.Trojan.BDFactory-5"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 0040a0e1000040e00270a0e3000000ef000050e30400a0e1044044e00070a0e30000000a[20-24]000000ef }
    condition:
		$a0 at manape.ep
}

rule Unix_dot_Trojan_dot_Mrblack_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Mrblack-1"
        sha256         = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 00020008 [-] 2d2d2d7365727665722025733a25642d2d2d [-] 56455253304e45583a25737c25647c25647c2573 [-] 4d722e426c61636b [-] 557365722d4167656e743a204d6f7a696c6c612f352e302b28636f6d70617469626c653b2b42616964757370696465722f322e303b2b2b687474703a2f2f7777772e62616964752e636f6d2f7365617263682f7370696465722e68746d6c29 [-] 706173737764 [-] 7075626c69636b6579 [-] 736861646f7700 }
    condition:
		$a0 at 16
}
