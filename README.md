# WannaCry|WannaDecrypt0r NSA-Cybereweapon-Powered Ransomware Worm 

* **Virus Name**: WannaCrypt, WannaCry, WanaCrypt0r, WCrypt, WCRY
* **Vector**: All Windows versions before Windows 10 are vulnerable if not patched for MS-17-010. It uses EternalBlue MS17-010 to propagate.
* **Ransom**: between $300 to $600. There is code to 'rm' (delete) files in the virus. Seems to reset if the virus crashes.
* **Backdooring**: The worm loops through every RDP session on a system to run the ransomware as that user. It also installs the DOUBLEPULSAR backdoor. (source: malwarebytes)
* **Kill switch**: If the website `www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com` is up the virus exits instead of infecting the host. (source: malwarebytes). This domain has been sinkholed, stopping the spread of the worm.

SECURITY BULLETIN AND UPDATES HERE: https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
https://blog.malwarebytes.com/threat-analysis/2017/05/the-worm-that-spreads-wanacrypt0r/

# Infections

* NHS (uk) turning away patients, unable to perform x-rays.
* Telefonica (spain)
* FedEx (us)
* University of Waterloo ([us](https://twitter.com/amtinits))
* Russia interior ministry & Megafon (russia)
* Сбера bank ([russia](https://twitter.com/discojournalist/status/863162464304865280))
* Shaheen Airlines (india, claimed on twitter)
* Train station in frankfurt ([germany](https://twitter.com/Nick_Lange_/status/863132237822394369))
* Neustadt station ([germany](https://twitter.com/MedecineLibre/status/863139139138531328))
* the entire network of German Rail seems to be affected ([@farbenstau](https://twitter.com/farbenstau/status/863166384834064384))
* [Russian Railroads (RZD)](https://twitter.com/vassgatov/status/863175723846176768), [VTB russian bank](https://twitter.com/vassgatov/status/863175506790952962)
* [Portugal Telecom](http://imgur.com/a/rR3b9)


# Malware samples

* hxxps://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100
* hxxps://transfer.sh/PnDIl/CYBERed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.EXE
* hxxps://transfer.sh/ZhnxR/CYBER1be0b96d502c268cb40da97a16952d89674a9329cb60bac81a96e01cf7356830.EXE (main dll)

Binary blob in PE crypted with pass 'WNcry@2ol7', credits to ens!

# Informative Tweets

* Sample released by ens: https://twitter.com/the_ens/status/863055007842750465
* Onion C&Cs extracted: https://twitter.com/the_ens/status/863069021398339584
* EternalBlue confirmed: https://twitter.com/kafeine/status/863049739583016960
* Shell commands: https://twitter.com/laurilove/status/863065599919915010
* Maps/stats: https://twitter.com/laurilove/status/863066699888824322
* Core DLL: https://twitter.com/laurilove/status/863072240123949059
* Hybrid-analysis: https://twitter.com/PayloadSecurity/status/863024514933956608
* Impact assessment: https://twitter.com/CTIN_Global/status/863095852113571840
* Uses DoublePulsar: https://twitter.com/laurilove/status/863107992425779202 
* Your machine is attacking others: https://twitter.com/hackerfantastic/status/863105127196106757
* Tor hidden service C&C: https://twitter.com/hackerfantastic/status/863105031167504385
* FedEx infected via Telefonica? https://twitter.com/jeancreed1/status/863089728253505539
* HOW TO AVOID INFECTION: https://twitter.com/hackerfantastic/status/863070063536091137
* More of this to come: https://twitter.com/hackerfantastic/status/863069142273929217
* C&C hosts: https://twitter.com/hackerfantastic/status/863115568181850113
* Crypted files *will* be deleted after countdown: https://twitter.com/laurilove/status/863116900829724672
* Claim of attrib [take with salt]: https://twitter.com/0xSpamTech/status/863058605473509378
* Track the bitcoins: https://twitter.com/bl4sty/status/863143484919828481
* keys in pem format: https://twitter.com/e55db081d05f58a/status/863109716456747008

# Cryptography details

* encrypted via AES-128-CBC (custom implementation in the binary)
* AES key generated with a CSPRNG, CryptGenRandom
* AES key is encrypted by RSA-2048 (windows RSA implementation)

* https://haxx.in/key1.bin (the ransomware pubkey, used to encrypt the aes keys)
* https://haxx.in/key2.bin (the dll decryption privkey)
the CryptImportKey() rsa key blob dumped from the DLL by blasty.

# Bitcoin ransom addresses

3 addresses hard coded into the malware.

* https://blockchain.info/address/13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94
* https://blockchain.info/address/12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw
* https://blockchain.info/address/115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn

# C&C centers

* `gx7ekbenv2riucmf.onion`
* `57g7spgrzlojinas.onion`
* `xxlvbrloxvriy2c5.onion`
* `76jdd2ir2embyv47.onion`
* `cwwnhwhlz52maqm7.onion`

# Languages

All language ransom messages available here: https://transfer.sh/y6qco/WANNACRYDECRYPTOR-Ransomware-Messages-all-langs.zip

m_bulgarian, m_chinese (simplified), m_chinese (traditional), m_croatian, m_czech, m_danish, m_dutch, m_english, m_filipino, m_finnish, m_french, m_german, m_greek, m_indonesian, m_italian, m_japanese, m_korean, m_latvian, m_norwegian, m_polish, m_portuguese, m_romanian, m_russian, m_slovak, m_spanish, m_swedish, m_turkish, m_vietnamese

# File types

The filetypes it looks for to encrypt are

.doc, .docx, .xls, .xlsx, .ppt, .pptx, .pst, .ost, .msg, .eml, .vsd, .vsdx, .txt, .csv, .rtf, .123, .wks, .wk1, .pdf, .dwg, .onetoc2, .snt, .jpeg, .jpg, .docb, .docm, .dot, .dotm, .dotx, .xlsm, .xlsb, .xlw, .xlt, .xlm, .xlc, .xltx, .xltm, .pptm, .pot, .pps, .ppsm, .ppsx, .ppam, .potx, .potm, .edb, .hwp, .602, .sxi, .sti, .sldx, .sldm, .sldm, .vdi, .vmdk, .vmx, .gpg, .aes, .ARC, .PAQ, .bz2, .tbk, .bak, .tar, .tgz, .gz, .7z, .rar, .zip, .backup, .iso, .vcd, .bmp, .png, .gif, .raw, .cgm, .tif, .tiff, .nef, .psd, .ai, .svg, .djvu, .m4u, .m3u, .mid, .wma, .flv, .3g2, .mkv, .3gp, .mp4, .mov, .avi, .asf, .mpeg, .vob, .mpg, .wmv, .fla, .swf, .wav, .mp3, .sh, .class, .jar, .java, .rb, .asp, .php, .jsp, .brd, .sch, .dch, .dip, .pl, .vb, .vbs, .ps1, .bat, .cmd, .js, .asm, .h, .pas, .cpp, .c, .cs, .suo, .sln, .ldf, .mdf, .ibd, .myi, .myd, .frm, .odb, .dbf, .db, .mdb, .accdb, .sql, .sqlitedb, .sqlite3, .asc, .lay6, .lay, .mml, .sxm, .otg, .odg, .uop, .std, .sxd, .otp, .odp, .wb2, .slk, .dif, .stc, .sxc, .ots, .ods, .3dm, .max, .3ds, .uot, .stw, .sxw, .ott, .odt, .pem, .p12, .csr, .crt, .key, .pfx, .der

credit herulume, thanks for extracting this list from the binary.

# Some other interesting strings 

BAYEGANSRV\administrator
Smile465666SA
wanna18@hotmail.com

credit: nulldot https://pastebin.com/0LrH05y2

# Encrypted file format

```
<64-bit SIGNATURE>        - WANACRY!
<length of encrypted key> - 256 for 2048-bit keys, cannot exceed 4096-bits
<encrypted key>           - 256 bytes if keys are 2048-bits
<32-bit value>            - unknown
<64 bit file size>        - return by GetFileSizeEx
<encrypted data>          - with custom AES-128 in CBC mode
```

credit for reversing this file format info: cyg_x11

# Vulnerability disclosure

The specific vulnerability that it uses to propagate is ETERNALBLUE.

This was developed by "equation group" an exploit developer group associated with the NSA and leaked to the public by "the shadow brokers". Microsoft fixed this vulnerability March 14, 2017. They were not 0 days at the time of release.

* https://blogs.technet.microsoft.com/msrc/2017/04/14/protecting-customers-and-evaluating-risk/
* https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
Credits: rain-1
