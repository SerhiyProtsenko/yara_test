import "hash"


rule Pdf_Dropper_Agent_8087592
{
    meta:
        
        title          = "Pdf.Dropper.Agent-8087592-0:73"
	hash           = "c6c2ddd65229a1a29df32cbd5b420e68"
        author         = "ClamAV"
        source         = "ClamAV"
        description    = ""
        created_date   = ""
        reference      = ""
    
    condition:
    		 filesize == 36086 and hash.md5(0,filesize) == "c6c2ddd65229a1a29df32cbd5b420e68"
}
// --
