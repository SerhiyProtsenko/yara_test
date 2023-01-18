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
rule Unix_dot_Trojan_dot_Rex_dash_3
{
    meta:
        
        title          = "Unix.Trojan.Rex-3"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 414e4420594f552057494c4c204e4556455220414741494e20484541522046524f4d205553 }
		$a1 = { 425443 }
		$a2 = { 5055424c4943204b4559 }
		$a3 = { 44446f532d6564 }
		$a4 = { 64727570616c }
		$a5 = { 656c6576617465 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4 and $a5)
}
// --
rule Unix_dot_Rootkit_dot_Umbreon_dash_4
{
    meta:
        
        title          = "Unix.Rootkit.Umbreon-4"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 62756c6c73686974 }
		$a1 = { 2f70726f632f25642f636d646c696e65 }
		$a2 = { 2f7573722f73686172652f6c6962632e736f2e302e76366c2e6c642d322e32322e736f }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Exploit_dot_CVE_2016_5195_dash_2
{
    meta:
        
        title          = "Unix.Exploit.CVE_2016_5195-2"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 70726f6373656c666d656d546872656164 }
		$a1 = { 6d616476697365546872656164 }
		$a2 = { 2f70726f632f73656c662f6d656d }
    condition:
		($a0 and $a1 and $a2)
}
// --
rule Unix_dot_Trojan_dot_Gafgyt_dash_111
{
    meta:
        
        title          = "Unix.Trojan.Gafgyt-111"
				sha256			 = "eed6d09eb3aeb70390e4bb7d48944546547e9f3dfdbb7a8b38b5796ff823d832"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 25642e25642e25642e2564 }
		$a1 = { 50494e47 }
		$a2 = { 504f4e47 }
		$a3 = { 50524f42494e47 }
		$a4 = { 4b494c4c4154544b }
		$a5 = { 4a554e4b }
		$a6 = { 434e43 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6)
}
// --
rule Unix_dot_Trojan_dot_Linux_DDoS_93_dash_2
{
    meta:
        
        title          = "Unix.Trojan.Linux_DDoS_93-2"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 10300be510301be5013003e2 }
		$a1 = { d0309fe5912383e0a331a0e1 }
		$a2 = { a4304be200308de5 }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_Linux_DDoS_93_dash_5364119_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Linux_DDoS_93-5364119-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 89????8b????83e00185c0 }
		$a1 = { bacdcccccc89c8f7e2 }
		$a2 = { 48c785????????0300000048c785????????00000000b800000000b?10000000 }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607517_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607517-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4d796e616d652d [0-10] 2d6973 }
		$a1 = { 62757379626f78 }
		$a2 = { 50524f545f455845437c50524f545f5752495445 [0-10] 6661696c65642e }
    condition:
		($a0 and $a1 and $a2)
}
// --
rule Unix_dot_Trojan_dot_Amnesia_dash_6247462_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Amnesia-6247462-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 667265656e6f64652e6e6574 }
		$a1 = { 65666e65742e6f7267 }
		$a2 = { 5669727475616c426f78 }
		$a3 = { 564d77617265 }
		$a4 = { 51454d55 }
		$a5 = { 7379735f76656e646f72 }
		$a6 = { 43726f73732057656220536572766572 }
		$a7 = { 434354565343414e4e4552 }
		$a8 = { 6675636b776869746568617473 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8)
}
// --
rule Unix_dot_Tool_dot_Extremeparr_dash_6296516_dash_0_dash_6296516_dash_1
{
    meta:
        
        title          = "Unix.Tool.Extremeparr-6296516-0-6296516-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4154000025732f257300 }
		$a1 = { 83c40c68[4]8d85[2]ffff508d85[2]ffff50e8[2]ffff83c40c68[4]8d85[2]ffff508d85[2]ffff50e8[2]ffff }
		$a2 = { 6a028d85[2]ffff508d85[2]ffff50e8[2]ffff83c40ce9 }
    condition:
		($a0 and (($a1 and #a1 > 20)) and $a2)
}
// --
rule Unix_dot_Trojan_dot_Spike_dash_6301360_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Spike-6301360-0"
				sha256			 = "045bc3234932589d5c9ba773146ff22275f28ab650ea8a495ec11473ef9a98b6"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 564552534f4e45583a }
		$a1 = { 494e464f3a30 }
		$a2 = { 736564202d69202d65202732206925732f257320737461727427202f6574632f696e69742e642f626f6f742e6c6f63616c }
		$a3 = { 4861636b6572 }
    condition:
		($a0 and $a1 and $a2 and $a3)
}
// --
rule Unix_dot_Trojan_dot_ProxyM_dash_6329136_dash_0
{
    meta:
        
        title          = "Unix.Trojan.ProxyM-6329136-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 383163343630333638316334363033362f383163343630333638316334363033362e61726d7634 }
		$a1 = { 383163343630333638316334363033362f383163343630333638316334363033362e69353836 }
		$a2 = { 383163343630333638316334363033362f383163343630333638316334363033362e6d36386b }
		$a3 = { 383163343630333638316334363033362f383163343630333638316334363033362e6d697073 }
		$a4 = { 383163343630333638316334363033362f383163343630333638316334363033362e6d697073656c }
		$a5 = { 383163343630333638316334363033362f383163343630333638316334363033362e706f7765727063 }
		$a6 = { 383163343630333638316334363033362f383163343630333638316334363033362e736834 }
		$a7 = { 383163343630333638316334363033362f383163343630333638316334363033362e7370617263 }
		$a8 = { 746674703a206170706c6574206e6f7420666f756e64 }
		$a9 = { 776765743a206170706c6574206e6f7420666f756e64 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8 and $a9)
}
// --
rule Unix_dot_Trojan_dot_ShellBind_dash_6333870_dash_0
{
    meta:
        
        title          = "Unix.Trojan.ShellBind-6333870-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 416363657373206772616e746564 }
		$a1 = { 48454144202f20485454502f312e30 }
		$a2 = { 69707461626c6573 }
		$a3 = { 456e7465722070617373776f7264 }
		$a4 = { 57656c63306d65 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4)
}
// --
rule Unix_dot_Trojan_dot_Iotreaper1_dash_6354389_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Iotreaper1-6354389-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 61646d696e }
		$a1 = { 77657275756f7177656975722e636f6d }
		$a2 = { 726d202d72202f7661722f6c6f67 }
		$a3 = { 726d202d66202f746d702f66747075706c6f61642e7368 }
		$a4 = { 6c6e202d73202f6465762f6e756c6c202f746d702f66747075706c6f61642e7368 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4)
}
// --
rule Unix_dot_Trojan_dot_Iotreaper2_dash_6354394_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Iotreaper2-6354394-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 656173795f61747461636b5f646e73 }
		$a1 = { 656173795f61747461636b5f756470 }
		$a2 = { 61747461636b5f61636b }
		$a3 = { 656173795f61747461636b5f73796e }
		$a4 = { 61747461636b28626f647929 }
		$a5 = { 6c6f63616c206c75615f75726c203d }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4 and $a5)
}
// --
rule Unix_dot_Tool_dot_Minerd_dash_6404314_dash_0
{
    meta:
        
        title          = "Unix.Tool.Minerd-6404314-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 55736167653a206d696e657264205b4f5054494f4e535d }
		$a1 = { 7374726174756d2b7463703a2f2f }
		$a2 = { 557365722d4167656e743a206370756d696e6572 }
		$a3 = { 626f6f6f6f6f }
		$a4 = { 626c616b65 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4)
}
// --
rule Unix_dot_Tool_dot_Miner_dash_6414491_dash_0
{
    meta:
        
        title          = "Unix.Tool.Miner-6414491-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 6c756f786b6578702e636f6d }
		$a1 = { 786d726967 }
    condition:
		$a0 and $a1
}
// --
rule Unix_dot_Trojan_dot_Ddostf_dash_6443160_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Ddostf-6443160-0"
				sha256			 = "b4f5a82133bcfb85b8185ce015c209ec43b70e027010ea6bf80585da9dd2e708"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 64646f732e7466 }
		$a1 = { 4465616c7769746844446f53 }
		$a2 = { 575a53594e5f466c6f6f64 }
		$a3 = { 49434d505f466c6f6f64 }
    condition:
		$a0 and $a1 and $a2 and $a3
}
// --
rule Unix_dot_Tool_dot_Miner_dash_6443173_dash_0
{
    meta:
        
        title          = "Unix.Tool.Miner-6443173-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 746f756368202d72202f62696e2f7368202f62696e2f776970656673 }
		$a1 = { 2f6574632f696e69742e642f776970656673 }
		$a2 = { 2f6574632f72632e642f7263362e642f533031776970656673 }
		$a3 = { 2f746d702f746d706e616d5f585858585858 }
    condition:
		$a0 and $a1 and $a2 and $a3
}
// --
rule Unix_dot_Worm_dot_Hakai_dash_6654627_dash_3
{
    meta:
        
        title          = "Unix.Worm.Hakai-6654627-3"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 5b48414b41495d }
		$a1 = { 5b6b696c6c65725d }
		$a2 = { 2f70696373646573632e786d6c }
		$a3 = { 2f6374726c742f446576696365557067726164655f31 }
		$a4 = { 2f484e4150312f }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4)
}
// --
rule Unix_dot_Trojan_dot_Rocke_dash_6683972_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Rocke-6683972-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 5f4c5750436f6f6b69654a617228 }
		$a1 = { 5f4d6f7a696c6c61436f6f6b69654a617228 }
		$a2 = { 735862617368 }
		$a3 = { 2e726f64617461 }
		$a4 = { 2e64796e616d6963 }
		$a5 = { 2e676f742e706c74 }
		$a6 = { 2e636f6d6d656e74 }
    condition:
		$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6
}
// --
rule Unix_dot_Packed_dot_XBash_dash_6690405_dash_1
{
    meta:
        
        title          = "Unix.Packed.XBash-6690405-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 7ee3fbcf9efd633f683f643f6c3f623f6a3f663f693f6d3f }
		$a1 = { 91ef931ad307e487e447e4c7e427e4a7e467e4e7e417643f }
		$a2 = { 1ebb06a85515e3d713d793d753d7d3d733d7b3d773d7f3d7 }
		$a3 = { cf9efd633f683f643f6c3f623f6a3f663f693f6d3f633f6b }
		$a4 = { b6fbb607b647b6c7b6e7b697b6d7b637b677b6f7b68fb64f }
		$a5 = { 3f643f6c3f623f6a3f663f693f6d3f633f6bb7db811dda91 }
		$a6 = { 931ad307e487e447e4c7e427e4a7e467e4e7e417643ff74b }
		$a7 = { ef931ad307e487e447e4c7e427e4a7e467e4e7e417643ff7 }
    condition:
		$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7
}
// --
rule Unix_dot_Trojan_dot_WellMess_dash_6706034_dash_0
{
    meta:
        
        title          = "Unix.Trojan.WellMess-6706034-0"
				sha256			 = "fd3969d32398bbe3709e9da5f8326935dde664bbc36753bd41a0b111712c0950"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 7372632f626f742f626f746c6962 }
		$a1 = { 626f746c69622e4145535f456e6372797074 }
		$a2 = { 626f746c69622e526563656976654d657373616765 }
		$a3 = { 626f746c69622e53656e642e66756e6331 }
		$a4 = { 626f746c69622e446f776e6c6f6164 }
		$a5 = { 706f7765726366672e657865 }
		$a6 = { 7664736c64722e657865 }
		$a7 = { 7365745f757365724167656e74 }
		$a8 = { 6765745f757365724167656e74 }
		$a9 = { 7365745f6865616c746854696d65 }
		$a10 = { 6765745f6865616c746854696d65 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4) or (($a5 or $a6) and ($a7 and $a8 and $a9 and $a10))
}
// --
rule Unix_dot_Trojan_dot_Gafgyt_dash_6735651_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Gafgyt-6735651-0"
				sha256			 = "220935a9c5f6de63ef0d7c63e6f9ba3033e962854ca1911e770de2578d3d7e35"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 2f7573722f62696e2f707974686f6e }
		$a1 = { 2f7573722f62696e2f7065726c }
		$a2 = { 2f7573722f7362696e2f74656c6e657464 }
		$a3 = { 2f6574632f6170742f6170742e636f6e66 }
		$a4 = { 2f6574632f79756d2e636f6e66 }
		$a5 = { 5b5368656c6c696e675d2d2d3e5b25735d2d2d3e5b25735d2d2d3e5b25735d2d2d3e5b25735d2d2d3e5b25735d }
    condition:
		$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}
// --
rule Unix_dot_Trojan_dot_CryptoMiner_dash_6742844_dash_0
{
    meta:
        
        title          = "Unix.Trojan.CryptoMiner-6742844-0"
				sha256			 = "92efa48191c1bb2e925d29220e38acfda0f014ff7e5486a04f12e87eab708887"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { B140F3ABC685[2]FFFF72C685[2]FFFF30C685[2]FFFF73C685[2]FFFF74C685[2]FFFF40C685[2]FFFF23C685[2]FFFF24C685[2]FFFF00 }
    condition:
		$a0
}
// --
rule Unix_dot_Malware_dot_Chalubo_dash_6748749_dash_1
{
    meta:
        
        title          = "Unix.Malware.Chalubo-6748749-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 736F636B65742E68747470 }
		$a1 = { 3A383835322F4153444652452F }
		$a2 = { 6C75615F7461736B5F75726C73 }
		$a3 = { 6B696C6C5F7461736B2829 }
    condition:
		$a0 and $a1 and $a2 and $a3
}
// --
rule Unix_dot_Trojan_dot_Coinminer_dash_6751745_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Coinminer-6751745-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 6375726c202d6673534c202d2d636f6e6e6563742d74696d656f7574 }
		$a1 = { 726f6f74202f62696e2f7368202f62696e2f68747470646e7322203e3e202f6574632f63726f6e746162 }
		$a2 = { 6e6f687570202f62696e2f7368202f62696e2f68747470646e73203e2f6465762f6e756c6c20323e26312026 }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_Agent_dash_6762136_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Agent-6762136-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 3130342e3234382e31342e323036 }
		$a1 = { 36382e3138332e36352e3536 }
		$a2 = { 3137382e3132382e33382e3932 }
		$a3 = { 3135392e36352e3234382e323137 }
		$a4 = { 3138352e3234342e32352e323532 }
		$a5 = { 3138382e3136362e37382e323236 }
		$a6 = { 3137332e3234392e322e3833 }
		$a7 = { 3130342e3234382e32322e3537 }
		$a8 = { 3136372e39392e3230312e313436 }
		$a9 = { 3130342e3234382e3232392e313532 }
		$a10 = { 34362e3130312e3230382e313533 }
		$a11 = { 3138352e3130312e3130372e323333 }
		$a12 = { 36342e3133372e3235312e313635 }
		$a13 = { 3230342e34382e32352e323334 }
		$a14 = { 38392e34362e3232332e3832 }
		$a15 = { 3230372e3135342e3231392e313132 }
		$a16 = { 36382e3138332e3131322e313335 }
    condition:
		($a0 or $a1 or $a2 or $a3 or $a4 or $a5 or $a6 or $a7 or $a8 or $a9 or $a10 or $a11 or $a12 or $a13 or $a14 or $a15 or $a16)
}
// --
rule Unix_dot_Dropper_dot_GoDropper_dash_6788148_dash_0
{
    meta:
        
        title          = "Unix.Dropper.GoDropper-6788148-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 52656c6561736566696c6573 }
		$a1 = { 4d795368656c6c436f646546696c65427566 }
    condition:
		$a0 and $a1
}
// --
rule Unix_dot_Trojan_dot_Miner_dash_6958810_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Miner-6958810-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 555058 }
		$a1 = { 6f30425558506c64532f697535594851484646786b5432504e6171587465f6ffffff }
		$a2 = { 394b4174704d33517a6638672f554a7042366b1264776c69742d4a6849ffffdbb7 }
    condition:
		$a0 and ($a1 or $a2)
}
// --
rule Unix_dot_Trojan_dot_Winnti_dash_6975334_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Winnti-6975334-0"
				sha256			 = "66923293d6cd7169d843e26aade13896ce77214fbe256bd925d7b96187b2aa48"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4465637279707432 }
		$a1 = { 666f70656e3634 }
		$a2 = { 6f75725f736f636b657473 }
		$a3 = { 6765745f6f75725f70696473 }
    condition:
		$a0 and $a1 and $a2 and $a3
}
// --
rule Unix_dot_Trojan_dot_Torte_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Torte-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 584456534e5f53455353494f4e5f434f4f4b4945 }
		$a1 = { 6538303766316663663832643133326639626230313863613637333861313966 }
		$a2 = { 6531313137306238636264326437343130323635316362393637666132386535 }
		$a3 = { 3361303866653762386334646136656430396632316333656639376566636532 }
		$a4 = { 83F00C }
		$a5 = { 83F002 }
		$a6 = { 426173653634 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6)
}
// --
rule Unix_dot_Exploit_dot_CVE_2010_3301_dash_2
{
    meta:
        
        title          = "Unix.Exploit.CVE_2010_3301-2"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 636f6d6d69745f6372656473 }
		$a1 = { 707265706172655f6b65726e656c5f63726564 }
		$a2 = { 2f70726f632f6b616c6c73796d73 }
		$a3 = { 2f62696e2f7368 }
		$a4 = { 707472616365 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4)
}
// --
rule Unix_dot_Trojan_dot_Snakso_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Snakso-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 7a7a7a7a7a7a5f636f6d6d616e645f687474705f696e6a6563745f666f725f6d6f64756c655f696e6974 }
		$a1 = { 696e6a656374 }
		$a2 = { 6f6b21 }
		$a3 = { 2f2e6b65726e656c5f76657273696f6e5f746d70 }
    condition:
		($a0 and $a1 and $a2 and $a3)
}
// --
rule Unix_dot_Exploit_dot_Iosjailbreak_dash_3
{
    meta:
        
        title          = "Unix.Exploit.Iosjailbreak-3"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 687474703a2f2f6576617369306e2e636f6d }
		$a1 = { 6950686f6e65 }
		$a2 = { 69506f6420546f756368 }
		$a3 = { 69506164 }
		$a4 = { 2f7661722f6d6f62696c652f4c6962726172792f4361636865732f636f6d2e6170706c652e6d6f62696c652e696e7374616c6c6174696f6e2e706c697374 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4)
}
// --
rule Unix_dot_Exploit_dot_Fsheep_dash_1
{
    meta:
        
        title          = "Unix.Exploit.Fsheep-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 0F01F8E8050000000F01F848CF }
		$a1 = { 2f62696e2f6261736800 }
		$a2 = { 2d736800 }
		$a3 = { 21736574756964283029 }
		$a4 = { 7364406675636b73686565702e6f72672032303130 }
    condition:
		$a0 and $a1 and $a2 and $a3 and $a4
}
// --
rule Unix_dot_Trojan_dot_Hanthie_dash_5
{
    meta:
        
        title          = "Unix.Trojan.Hanthie-5"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 25732f25732e25732e636f6e6669670025732f2e6b6465002f70726f632f73656c662f636d646c696e650025732f6175746f7374617274[18]25732f257325732e6465736b746f700025732f4175746f7374617274[65]6b696c6c616c6c20756e697864[53]6b696c6c616c6c20756e69782d6461656d6f6e[51]6b696c6c616c6c2070307374666978 }
		$a1 = { 25732f257325732e6465736b746f700025732f4175746f73746172740072002f70726f632f736373692f73637369002573256300564d776172650056424f58002f70726f632f637075696e666f00554d4c00506f776572564d204c7838360049424d2f533339300051454d55002f70726f632f737973696e666f00564d00436f6e74726f6c2050726f6772616d004c504152002f70726f632f767a002f70726f632f6263002f70726f632f78656e2f6361706162696c6974696573002f70726f632f312f6d6f756e74696e666f002f70726f632f25642f6d6f756e74696e666f }
		$a2 = { 25732f25732e25732e636f6e6669670025732f2e6b6465002f70726f632f73656c662f636d646c696e65[22]25736964656e746974792573006964656e74697479006c69626e737072342e736f0028732900504f5354202f00474554202f00687474703a2f2f006170706c69636174696f6e2f6f6373702d726571756573740068747470733a2f2f }
    condition:
		($a0 or $a1 or $a2)
}
// --
rule Unix_dot_Trojan_dot_Tsunami_dash_7
{
    meta:
        
        title          = "Unix.Trojan.Tsunami-7"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 2f746d702f74616e2e706964 }
		$a1 = { 72616674 }
		$a2 = { 237261696c73 }
    condition:
		($a0 and $a1 and $a2)
}
// --
rule Unix_dot_Trojan_dot_Ebury_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Ebury-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4c89e74889c64d89f5e81dfaffff4885c04989c474a84c89ea4c89e689dfe8d0f1ffff4885c04989c679d04c89e7e8f0f0ffffb8ffffffff }
		$a1 = { 488d35??3a000048894424184889c2 }
		$a2 = { 488d3d??3a0000b908000000f3a674 }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_Ebury_dash_2
{
    meta:
        
        title          = "Unix.Trojan.Ebury-2"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4c63f031ed41ffc7eb23418b34244c8b4424104489fa488b4c24084489ef4983c4044983ee04e8e2feffff01c54983fe0377d7488bbc24280100 }
		$a1 = { 488d35e236000031c04889eac644242000 }
		$a2 = { 488d35ac3600004889efe874f4ffff }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_IptabLex_dash_1
{
    meta:
        
        title          = "Unix.Trojan.IptabLex-1"
				sha256			 = "b5745c865ab5348425e79ce91d79442982c20f3f89e1ffcdd2816895a25d2a1c"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 66696e64202f202d6e616d65202e49707461624c6573207c20786172677320726d202d66 }
		$a1 = { 66696e64202f202d6e616d65202a707461624c6573207c20786172677320726d202d66 }
		$a2 = { 726d202d66202f626f6f742f49707461624c65(73|78) }
    condition:
		($a0 and $a1 or $a2)
}
// --
rule Unix_dot_Trojan_dot_Onimiki_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Onimiki-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 430FB6742A0E430FB60C2A8D7C3D008D }
		$a1 = { 7435008D4C0D0089F841F7E389F829D0 }
		$a2 = { D1E801C289F0C1EA04448D0C92468D0C }
		$a3 = { 8A41F7E389F04429CF29D0D1E801C289 }
		$a4 = { C8C1EA04448D0492468D048241F7E389 }
		$a5 = { C84429C629D0D1E801C2C1EA048D0492 }
		$a6 = { 8D048229C1420FB6042142888414C001 }
		$a7 = { 0000420FB6042743880432420FB60426 }
		$a8 = { 42888414A00100004983C2014983FA07 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8)
}
// --
rule Unix_dot_Trojan_dot_Trula_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Trula-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 545245585f5049443d2575 }
		$a1 = { 52656d6f746520565320697320656d7074792021 }
    condition:
		$a0 and $a1
}
// --
rule Unix_dot_Trojan_dot_Flooder_dash_353
{
    meta:
        
        title          = "Unix.Trojan.Flooder-353"
				sha256			 = "751f42e1303ba2e365cf95ac9b859ec74160133d6ea6ffda962a924e975228e4"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 466C6F6F6420436F64656420427920416E6369656E744D696467657473 }
		$a1 = { 5374617274696E6720466C6F6F64 }
		$a2 = { 488B45E80FB7000FB7C0480145F8488345E802836DE401 }
    condition:
		$a0 or ($a1 and $a2)
}
// --
rule Unix_dot_Trojan_dot_Concbak_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Concbak-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 2F676174652E706870 }
		$a1 = { 2670636E616D653D00 }
		$a2 = { 26687769643D00 }
		$a3 = { 756470666C6F6F6400 }
		$a4 = { 6261636B636F6E6E65637400 }
		$a5 = { 2F6574632F736861646F7700 }
    condition:
		($a0 and $a1 and $a2) and ($a3 or $a4 or $a5)
}
// --
rule Unix_dot_Trojan_dot_ChinaZ_dash_2
{
    meta:
        
        title          = "Unix.Trojan.ChinaZ-2"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 434f4d4d414e445f44444f535f53544f50 }
		$a1 = { 4368696e615a }
		$a2 = { 636f6e6e65637420746f207365727665722e2e2e }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Legacy_dot_Trojan_dot_Agent_dash_1388639
{
    meta:
        
        title          = "Legacy.Trojan.Agent-1388639"
				sha256			 = "ea2440ddf18c5754d286e0daa366e0a34f4a31c7531cf94dafb2eaed6148ba2a"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 83ec0468[3]0868[3]0868[3]08e8[2]010083c41083ec0c68[3]08e864??010083c41083ec0c68[3]08e8[2]010083c41083ec0c68[3]08e8[3]0083c410e8[2]0100 }
		$a1 = { 83ec0c8d45??50e8[3]0083c41083ec0c8d45e?50e8[2]020083c4 [0-4] 50e8[3]0083c410 [0-3] 84c0 }
    condition:
		$a0 and $a1
}
// --
rule Unix_dot_Trojan_dot_DDoS_XOR_dash_1
{
    meta:
        
        title          = "Unix.Trojan.DDoS_XOR-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 736564202D6920272F5C2F6574635C2F63726F6E2E686F75726C795C2F [0-10] 2E73682F6427202F6574632F63726F6E746162202626206563686F20272A2F33202A202A202A202A20726F6F74202F6574632F63726F6E2E686F75726C792F [0-10] 2E736827203E3E202F6574632F63726F6E746162 }
		$a1 = { 557365722D4167656E743A204D6F7A696C6C612F342E302028636F6D70617469626C653B204D53494520362E303B2057696E646F7773204E5420352E323B205356313B2054656E63656E7454726176656C6572203B202E4E455420434C5220312E312E3433323229 }
    condition:
		$a0 and $a1
}
// --
rule Unix_dot_Trojan_dot_Mumblehard_dash_3
{
    meta:
        
        title          = "Unix.Trojan.Mumblehard-3"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 8925099A0408B80D00000031DB5350CD807302F7D881C4080000003D000000007C07B003E902000000B009A20D9A0408BEF5820408B90D000000E879000000E89E000000BE03830408B906170000E865000000B8040000008B1D1A9A0408B903830408BA0617000052515350CD807302F7D881C4100000003D000000000F8C2C00000039D00F8524000000B8060000008B1D1A9A04085350CD807302F7D881C4080000003D000000000F8C0000000031C04031DB5350CD8031DB4343BA10000000565F39D3751381FA80000000750231D281C21000000031DB43AC30D8AA43E2 }
		$a1 = { 8A0DD5460508B82A000000BBD64605085350CD807302F7D881C4080000003D000000000F8CA4FFFFFF80F90975058903895304B82A000000BBDE4605085350CD807302F7D881C4080000003D000000000F8C77FFFFFF80F90975058903895304 }
		$a2 = { 8A0DF9B80508B82A000000BBFAB805085350CD807302F7D881C4080000003D000000000F8CCEFFFFFF80F90975058903895304B82A000000BB02B905085350CD807302F7D881C4080000003D000000000F8CA1FFFFFF80F90975058903895304B8020000005080F909750BCD807302F7D8E902000000CD8081C4040000003D000000000F8C6EFFFFFF0F8449000000B8060000008B1DFEB805085350CD807302 }
		$a3 = { 81C40C0000003D000000000F8CE8FEFFFFB83F00000080FA097505B85A0000008B1DDEAB050831C941515350CD807302F7D881C40C0000003D000000000F8CB6FEFFFFB8060000008B1DDAAB05085350 }
		$a4 = { B80D00000031DB5350CD807302F7D8909081C4080000003D000000007C07B003E902000000B009A2119A0408BEF9820408B90D000000E879000000E8A0000000 }
    condition:
		$a0 or $a1 or $a2 or $a3 or $a4
}
// --
rule Unix_dot_Exploit_dot_CVE_2016_0728_dash_1
{
    meta:
        
        title          = "Unix.Exploit.CVE_2016_0728-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 6c69626b65797574696c73 [0-194] 6b657963746c }
		$a1 = { 837de4fc }
		$a2 = { 6888000000 [0-96] 837de43f }
		$a3 = { b8fcffffff483945e8 }
		$a4 = { ba88000000 [0-95] 48837de83f }
    condition:
		$a0 and (($a1 and $a2) or ($a3 and $a4))
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Mirai-1"
				sha256			 = "f4da179e4dad8e9513edbfc5be6ca2af6838069405bfede2a52d6c9ce1100d5d"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 2f6465762f7761746368646f67 }
		$a1 = { 2f70726f632f6e65742f746370 }
		$a2 = { 006f67696e }
		$a3 = { 656e746572 }
		$a4 = { 00617373776f7264 }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4)
}
// --
rule Unix_dot_Trojan_dot_ChinaZ_dash_3
{
    meta:
        
        title          = "Unix.Trojan.ChinaZ-3"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 31303939326675636b }
		$a1 = { 466c6f6f64696e672e2e2e }
		$a2 = { 232323554450204675636b6572232323 }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_KillDisk_dash_5542459_dash_1
{
    meta:
        
        title          = "Unix.Trojan.KillDisk-5542459-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 554889e54883ec2048897d??c745??00000000bf00000000e8[4]89c7e8[4]c745??00000000eb40e8[4]8945??8b45??4863d0488b45??4801d0660fefc0f20f2a45??f20f100d[4]f20f5ec1f20f100d[4]f20f59c1f20f2cd088108345??01837d????7eba90c9c3 }
		$a1 = { 72616e6400 }
		$a2 = { 7372616e6400 }
		$a3 = { 74696d6500 }
    condition:
		$a0 and $a1 and $a2 and $a3
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607474_dash_2
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607474-2"
				sha256			 = "d5601202dff3017db238145ff21857415f663031aca9b3d534bec8991b12179a"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 2f70726f63 [0-10] 2f6e6574 }
		$a1 = { 69707461626c6573 }
		$a2 = { 74656c6e657464 }
		$a3 = { 5b6d6f64756c65735d }
		$a4 = { 5b70656572735d }
    condition:
		((($a0 and #a0 > 2)) and $a1 and $a2 and (($a3 and #a3 > 1)) and (($a4 and #a4 > 1)))
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607483_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607483-0"
				sha256			 = "1e6597b817553c0ba8a06bec334f8ce6558473a72a77a1708ab9cc445b542fef"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 2f70726f63 [0-10] 2f6e6574 }
		$a1 = { 4743433a }
		$a2 = { 77676574 [0-50] 63686d6f64 [0-10] 373737 }
    condition:
		($a0 and (($a1 and #a1 > 20)) and $a2)
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607487_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607487-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 73696d756c7461696e696f757320636f6e6e656374696f6e73 }
		$a1 = { 7365727665722070617373776f72642066696c65 }
		$a2 = { 68656170 }
    condition:
		($a0 and (($a1 and #a1 > 2)) and (($a2 and #a2 > 10)))
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607488_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607488-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4d796e616d65 [0-10] 2d2d [0-10] 6973 }
		$a1 = { 50524f545f455845437c50524f545f5752495445 }
		$a2 = { 69707461626c6573 }
    condition:
		($a0 and $a1 and $a2)
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607489_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607489-0"
				sha256			 = "c17348bd3d09e2bc28f92de1bf8ebda4fed4673e9354b50b99e2959848e529b5"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 466c6f6f64696e67 [0-10] 666f72 [0-10] 7365636f6e6473 }
		$a1 = { 70726f63 [0-10] 6e6574 }
		$a2 = { 4743433a }
    condition:
		((($a0 and #a0 > 2)) and $a1 and (($a2 and #a2 > 10)))
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607490_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607490-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 796e616d65 [0-10] 2d2d [0-10] 6973 }
		$a1 = { 69707461626c6573 }
		$a2 = { 50524f545f455845437c50524f545f5752495445 }
    condition:
		($a0 and $a1 and $a2)
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607491_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607491-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 656c662f657865 }
		$a1 = { 796e616d [0-10] 652d2d6973 }
		$a2 = { 50524f545f455845437c50524f545f5752495445 }
    condition:
		($a0 and $a1 and $a2)
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607492_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607492-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 50524f545f455845437c50524f545f5752495445 [0-10] 6661696c65642e }
		$a1 = { 4152544f46 [0-10] 574152 }
    condition:
		($a0 and $a1)
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607495_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607495-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4d796e61 [0-10] 6d652d2d6973 }
		$a1 = { 62757379626f78 }
		$a2 = { 50524f545f455845437c50524f545f5752495445 [0-10] 6661696c65642e }
    condition:
		($a0 and $a1 and $a2)
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607530_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607530-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 616d652d2d69733a }
		$a1 = { 69707461626c [0-10] 6573202d4120494e }
		$a2 = { 50524f545f455845437c50524f545f5752495445 [0-10] 6661696c65642e }
    condition:
		($a0 and $a1 and $a2)
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607531_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607531-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 616d652d2d69733a }
		$a1 = { 6970746162 [0-10] 6c6573202d412049 }
		$a2 = { 50524f545f455845437c50524f545f5752495445 [0-10] 6661696c65642e }
    condition:
		($a0 and $a1 and $a2)
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607534_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607534-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 666c6f6f64 }
		$a1 = { 7061636b6574696e6720636f6d706c65746564 }
		$a2 = { 50524f545f455845437c50524f545f5752495445 [0-10] 6661696c65642e }
    condition:
		((($a0 and #a0 > 2)) and (($a1 and #a1 > 2)) and $a2)
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5607535_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5607535-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4d796e616d [0-10] 652d2d6973 }
		$a1 = { 6970746162 [0-10] 6c6573202d412049 }
		$a2 = { 50524f545f455845437c50524f545f5752495445 [0-10] 6661696c65642e }
    condition:
		($a0 and $a1 and $a2)
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5678467_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5678467-0"
				sha256			 = "f4da179e4dad8e9513edbfc5be6ca2af6838069405bfede2a52d6c9ce1100d5d"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 62696e73 [0-10] 6d69726169 }
		$a1 = { 6b616c69 [0-10] 6d69726169 }
    condition:
		$a0 or $a1
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5889529_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5889529-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 6e616d652d2d6973 }
		$a1 = { 626f782069707461 }
		$a2 = { 626c6573202d41 }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5889548_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5889548-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 53544f504b545441 }
		$a1 = { 50494e47 }
		$a2 = { 504f4e47 }
    condition:
		$a0 and (($a1 and #a1 == 2)) and $a2
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5932144_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5932144-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 617373776f7264 }
		$a1 = { 6f67696e }
		$a2 = { 6b696c6c616c6c }
		$a3 = { 4d796e616d652d2d69733a }
    condition:
		$a0 and $a1 and (($a2 and #a2 > 1)) and $a3
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5932146_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5932146-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4d796e61 [0-50] 6d652d2d69733a }
		$a1 = { 75726c3d }
    condition:
		$a0 and $a1
}
// --
rule Unix_dot_Trojan_dot_Mirai_dash_5932147_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Mirai-5932147-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4d796e616d652d2d }
		$a1 = { 65786531 }
		$a2 = { 486f73743a }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Tool_dot_NOPEN_dash_6290440_dash_0
{
    meta:
        
        title          = "Unix.Tool.NOPEN-6290440-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { a9cfbba9cf00 }
		$a1 = { 302e392e3564 }
		$a2 = { 616d }
		$a3 = { 612e6d2e }
		$a4 = { 706d }
		$a5 = { 702e6d2e }
    condition:
		$a0 and $a1 and ($a2 or $a3) and ($a4 or $a5)
}
// --
rule Unix_dot_Tool_dot_NOPEN_dash_6290441_dash_0
{
    meta:
        
        title          = "Unix.Tool.NOPEN-6290441-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 2d6275726e4255524e }
		$a1 = { 4e4f50454e20736572766572 }
		$a2 = { 4e4f50454e20636c69656e74 }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_SSHScan_dash_6335682_dash_0
{
    meta:
        
        title          = "Unix.Trojan.SSHScan-6335682-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 76756c6e2e747874 }
		$a1 = { 706173735f66696c65 }
		$a2 = { 69645f727361 }
		$a3 = { 756e616d6520202d72202d73 }
		$a4 = { 556e64652d69 }
		$a5 = { 6d66752e747874 }
		$a6 = { 756e69712e747874 }
		$a7 = { 4f70656e53534c }
    condition:
		($a0 and $a1 and $a2 and $a3 and $a4 and ($a5 or $a6) and (($a7 and #a7 > 15)))
}
// --
rule Multios_dot_Exploit_dot_Spectre_dash_6414719_dash_0
{
    meta:
        
        title          = "Multios.Exploit.Spectre-6414719-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 8b4decbaabaaaa2a89c8f7ea89c8c1f81f29c289d001c001d001c029c189ca8d42ff66b800004898488945d8488b45d848c1e810480945d8488b4590483345e0482345d8483345e0488945d8488b45d84889c7e89a }
		$a1 = { 488b45f84805[4]0fb6000fb6c0c1e00948980fb690c01560000fb605710b200021d08805690b2000 }
    condition:
		$a0 and $a1
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_dash_6425811_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter-6425811-0"
				sha256			 = "50ac4fcd3fbc8abcaa766449841b3a0a684b3e217fc40935f1ac22c34c58a9ec"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 2f6574632f7265736f6c762e636f6e66 }
		$a1 = { 6e616d65736572766572 }
		$a2 = { 6e7078586f756469664665456747614143536e6373 }
		$a3 = { 557365722d4167656e743a204d6f7a696c6c612f[1]2e[1]2028636f6d70617469626c653b204d53494520[1]2e[1]3b2057696e646f7773204e5420[1]2e[1]3b2054726964656e742f[1]2e[1]29 }
		$a4 = { 506f6c617253534c }
    condition:
		$a0 and $a1 and $a2 and $a3 and $a4
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_dash_6425812_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter-6425812-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 2f746d556e626c6f636b2e636769 }
		$a1 = { 25732f7265705f25752e62696e }
		$a2 = { 50617373776f72643d }
		$a3 = { 417574686f72697a6174696f6e3a204261736963 }
    condition:
		$a0 and $a1 and $a2 and $a3
}
// --
rule Unix_dot_Malware_dot_Chaos_dash_6474902_dash_0
{
    meta:
        
        title          = "Unix.Malware.Chaos-6474902-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 657865632062617368202d6900 }
		$a1 = { 6a303000 }
		$a2 = { 6a3000 }
		$a3 = { 00637279707400 }
		$a4 = { 00636f6e6e65637400 }
		$a5 = { 006b696c6c00 }
		$a6 = { 006c697374656e00 }
		$a7 = { 0069736174747900 }
    condition:
		($a0 and ($a1 or $a2) and ($a3 and $a4 and $a5 and $a6 and $a7))
}
// --
rule Unix_dot_Exploit_dot_CVE_2017_7494_dash_6475571_dash_0
{
    meta:
        
        title          = "Unix.Exploit.CVE_2017_7494-6475571-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 48656c6c6f2066726f6d207468652053616d6261206d6f64756c6521 }
		$a1 = { 737061776e5f726576657273655f7368656c6c }
    condition:
		$a0 and $a1
}
// --
rule Unix_dot_Exploit_dot_CVE_2018_10561_dash_6541278_dash_0
{
    meta:
        
        title          = "Unix.Exploit.CVE_2018_10561-6541278-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 79597a3557647535576531704862756b335a4145 }
		$a1 = { 2f47706f6e466f726d2f646961675f466f726d3f696d616765732f }
		$a2 = { 2f6465762f6e756c6c }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_dash_6550590_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter-6550590-0"
				sha256			 = "50ac4fcd3fbc8abcaa766449841b3a0a684b3e217fc40935f1ac22c34c58a9ec"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4d49494654544343417a576741774942416749424154414e42676b71686b69473977304241515546414442414d517377435159445651514745774a56557a4553 }
		$a1 = { 6d4f7374435844724f6f68545a70644233313953626c385748764b6c2b355779496e3754422b4e425368366c66753039346e4f776158584e4567374b63493363 }
		$a2 = { 374b345347536a6c61356367387831444238772f515a3836464b4f672f52795a736a52644a543664416a7a5939355168653773347376316432344a6c43536464 }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_dash_6550591_dash_2
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter-6550591-2"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4745542025733f6d653d257320485454502f312e310d0a486f73743a2025730d0a4163636570743a202a2f2a0d0a557365722d4167656e743a20 }
    condition:
		$a0
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_dash_6550592_dash_1
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter-6550592-1"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 255e3a64 }
		$a1 = { 67262a6b646a246467305f4040372778 }
		$a2 = { 2f62696e2f617368 }
		$a3 = { 2f62696e2f62617368 }
		$a4 = { 2f62696e2f7368656c6c }
		$a5 = { 506f6c617253534c }
    condition:
		($a0 or $a1) and $a2 and $a3 and $a4 and $a5
}
// --
rule Unix_dot_Packed_dot_Botnet_dash_6566031_dash_0
{
    meta:
        
        title          = "Unix.Packed.Botnet-6566031-0"
				sha256			 = "4028e729748c3aac1611a6117fcf2c16ef56bd0e86b178d541d55e5810a755ac"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 474554202F7365747570 }
		$a1 = { 2e6367693F6E6578745F66696C653D }
		$a2 = { 26746F646F3D737973636D6426 }
		$a3 = { 2F3B[1-16]247B4946537D }
    condition:
		$a0 and $a1 and $a2 and $a3
}
// --
rule Unix_dot_Dropper_dot_Botnet_dash_6566040_dash_0
{
    meta:
        
        title          = "Unix.Dropper.Botnet-6566040-0"
				sha256			 = "4028e729748c3aac1611a6117fcf2c16ef56bd0e86b178d541d55e5810a755ac"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 474554202f73657475702e6367693f6e6578745f66696c653d[5-16]26746f646f3d737973636d6426636d643d }
		$a1 = { 26637572706174683d2f2663757272656e7473657474696e672e68746d3d31 }
		$a2 = { 2f6367692d62696e2f3b[1-16]247b4946537d }
		$a3 = { 474554202F7368656C6C3F }
		$a4 = { 474554202f6c616e67756167652f[3-12]247b4946537d2626 }
		$a5 = { 2626746172247b4946537d2f737472696e672e6a7320485454502f312e30 }
    condition:
		$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_dstr_dash_6596220_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter_dstr-6596220-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 76706e66696c746572 }
		$a1 = { 726d202d7266202f2a }
		$a2 = { 2f6d7376662e706964 }
		$a3 = { 2f636c69656e745f63612e637274 }
    condition:
		$a0 and $a1 and $a2 and $a3
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_htpx_dash_6596262_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter_htpx-6596262-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 687470782e706964 }
		$a1 = { 436f6e74656e742d547970653a206170706c69636174696f6e2f782d6d73646f732d70726f6772616d }
		$a2 = { 69707461626c6573202d74206e6174202d4920505245524f5554494e47202d7020746370202d2d64706f7274203830202d6a205245444952454354202d2d746f2d706f72742038383838 }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_ndbr_dash_6598711_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter_ndbr-6598711-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 6e6462722e706964 }
		$a1 = { 2764726f706265617227202d207468652044726f706265617220736572766572 }
		$a2 = { 5573616765202573202d69702a203c69702d616464723a203139322e3136382e302e312f69702d72616e67653a203139322e3136382e302e302f32343e202d702a203c706f72743a2038302f706f72742d72616e67653a2032352d3132353e202d6e6f70696e67203c64656661756c74207965733e202d746370203c64656661756c742073796e3e202d73203c736f757263652069703e202d682f2d2d68656c7020287072696e7420746869732068656c7029 }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_ssler_dash_6598712_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter_ssler-6598712-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 73736c65722a }
		$a1 = { 64756d703a }
		$a2 = { 736974653a }
		$a3 = { 686f6f6b3a }
		$a4 = { 69707461626c6573202d74206e6174202d4920505245524f5554494e47202d7020746370202d2d64706f7274203830202d6a205245444952454354202d2d746f2d706f72742038383838 }
    condition:
		$a0 and $a1 and $a2 and $a3 and $a4
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_nm_dash_6598714_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter_nm-6598714-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 2f72657073635f25752e62696e }
		$a1 = { 227363616e223a5b }
		$a2 = { 22706f727473223a5b }
    condition:
		$a0 and $a1 and $a2
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_netfilter_dash_6599563_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter_netfilter-6599563-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 33312e31332e36342e35312f3332 }
		$a1 = { 3136392e34342e33362e302f3235 }
		$a2 = { 3230332e3230352e3136372e302f3234 }
		$a3 = { 35322e302e302e302f3136 }
		$a4 = { 33312e31332e36342e35312f3332 }
		$a5 = { 6c696269707463207625732e2025752062797465732e }
    condition:
		$a0 and $a1 and $a2 and $a3 and $a4 and $a5
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_portforwarding_dash_6599587_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter_portforwarding-6599587-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 69707461626c6573202d74206e6174202d4920505245524f5554494e472031202d7020746370202d6d20746370202d64202573202d2d64706f727420256875202d6a20444e4154202d2d746f2d64657374696e6174696f6e2025733a256875 }
		$a1 = { 69707461626c6573202d74206e6174202d4920504f5354524f5554494e472031202d7020746370202d6d20746370202d64202573202d2d64706f727420256875202d6a20534e4154202d2d746f2d736f75726365202573 }
		$a2 = { 5b6b776f726b65722f303a315d }
		$a3 = { 6e7078586f756469664665456747614143536373 }
    condition:
		$a0 and $a1 and $a2 and $a3
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_socks5proxy_dash_6599614_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter_socks5proxy-6599614-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 2d702c202d2d706f7274203c706f72743e202020202020202073657276657220706f72742c2064656661756c7420746f2031303830 }
		$a1 = { 75646e735f70617273652e63 }
		$a2 = { 28226c696265763a20 }
		$a3 = { 7373736572766572 }
    condition:
		$a0 and $a1 and $a2 and $a3
}
// --
rule Unix_dot_Trojan_dot_Vpnfilter_tcpvpn_dash_6606298_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Vpnfilter_tcpvpn-6606298-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 213b482a724b7c5f4d77532b45212d215e79433d794a54682e6b653a56796e457a2d7e3b3a2d513b6b515e775e2d7e533b51455a68365e6a67665f34527a7347 }
    condition:
		$a0
}
// --
rule Unix_dot_Trojan_dot_Gafgyt_dash_6748839_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Gafgyt-6748839-0"
				sha256			 = "4028e729748c3aac1611a6117fcf2c16ef56bd0e86b178d541d55e5810a755ac"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 504f5354202f47706f6e466f726d2f646961675f466f726d3f696d616765732f20485454502f312e31 }
		$a1 = { 557365722d4167656e743a2048656c6c6f2c20576f726c64 }
    condition:
		$a0 and $a1
}
// --
rule Unix_dot_Trojan_dot_Kowai_dash_6748840_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Kowai-6748840-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4b6f7761692076322062792066617261646179202620736c756d70 }
		$a1 = { 2f62696e2f62757379626f782077676574202d6720 }
    condition:
		$a0 and $a1
}
// --
rule Unix_dot_Trojan_dot_Coinminer_dash_6964768_dash_0
{
    meta:
        
        title          = "Unix.Trojan.Coinminer-6964768-0"
				sha256			 = ""
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    strings:
		$a0 = { 4a616c617266 }
		$a1 = { 62585248664838 }
		$a2 = { 526564204861742f2d323329 }
		$a3 = { 2d65206d61676e }
		$a4 = { 4743433a2028474e552920342e }
    condition:
		$a0 and $a1 and $a2 and $a3 and $a4
}
// --
