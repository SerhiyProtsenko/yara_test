import "hash"


rule Pdf_Dropper_Agent_8087592
{
    meta:
        
        title          = "Pdf.Dropper.Agent-8087592-0:73"
	hash           = "c6c2ddd65229a1a29df32cbd5b420e68"
	sha1           = "ea12d9bc365e84358ca037f03cc1107138b6fddb"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    
    condition:
    		 filesize == 36086 and hash.md5(0,filesize) == "c6c2ddd65229a1a29df32cbd5b420e68"
}
// --
