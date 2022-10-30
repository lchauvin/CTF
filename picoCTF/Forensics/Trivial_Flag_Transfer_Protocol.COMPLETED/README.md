# Trivial Flag Transfer Protocol

Laurent Chauvin | October 28, 2022

## Resources

[1] https://www.dcode.fr/cipher-identifier

## Progress

```
wget https://mercury.picoctf.net/static/ed308d382ae6bcc37a5ebc701a1cc4f4/tftp.pcapng
wireshark tftp.pcapng
```

From here, go to File -> Export Object -> TFTP

Save all.

Inside program.deb is the steghide program.

Tried to run it on pictures but need a passphrase.

Instructions and plan seems to be encoded.

Used [1] to identify cipher type.

Using a rot-13 on Instructions.txt yields:

```
TFTP DOESNT ENCRYPT OUR TRAFFIC SO WE MUST DISGUISE OUR FLAG TRANSFER. FIGURE OUT A WAY TO HIDE THE FLAG AND I WILL CHECK BACK FOR THE PLAN
```

Plan reads:

```
I USED THE PROGRAM AND HID IT WITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS
```

Checking the photos with binwalk:

```
binwalk picture1.bmp 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PC bitmap, Windows 3.x format,, 605 x 454 x 24

```

```
binwalk picture2.bmp

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PC bitmap, Windows 3.x format,, 4032 x 3024 x 24
2815484       0x2AF5FC        Broadcom header, number of sections: 793596227,
5539633       0x548731        rzip compressed data - version 87.76 (1415270489 bytes)
6120249       0x5D6339        LANCOM OEM file
8201345       0x7D2481        LANCOM firmware header, model: "QXKRYLQXKQXKQWKOUJNTIKQFIODIODJPELRGMSHMSHMSHLRGJPEHNCIODNTIRXMRXMZbWgqejuinznkwkiuiqxmlmcOPFCD:@@6?>4@?5A>5B?6A>5?<3>;2>;2>;2>;", firmware version: "JPWJ", RC74, build 87 ("OVIPWJQX")
8249741       0x7DE18D        LANCOM firmware header, model: "OVJPXMPXMPXMPXMPXMOWLOWLPXMOWLOWLOWLPXMOWLOWLQYNT\Q[eY]j^arefwjbsf`maWaU=D9/3(8:0:;1AB8=>4>>4=<2<;1<90>;2=:1=:1=:1>;2?<3?<3?<3?<", firmware version: "KPWJ", RC73, build 88 ("NUHOVIQX")
8273945       0x7E4019        LANCOM firmware header, model: "X`UU]RT\QV^SW_TU]RS[PT\QV^SV^SV^S[eYal`eqeduhdxkfzmi}pj|om{odoc`h]T[PAG<:?4:>39:0;:0=<2=<2=<2<90;8/<90?<3A>5@=4?<3?<3>;2=:1>;2?<", firmware version: "TYaV", RC77, build 95 ("PWJRYMT\")
10291544      0x9D0958        Broadcom header, number of sections: 324294729,
12727226      0xC233BA        StuffIt Deluxe Segment (data): fVefVefVefVdeUcdT`aQ_`P``Ra`R`_Q`_QbaScbTebVfbWb^Sa]R_[P[VMTOFQLCTNDYSHWQFWQFWQEWQDWQD[UH_YL`ZM_YL]WJ]WJ\VI]WJ]WJ^XK_YLc]PlfYnh[
13247747      0xCA2503        StuffIt Deluxe Segment (data): fVdeUbcS`aQ_`P_`P``PaaQ``P``P__O__O^^N^^N^^N^^N\\L[[KYYI\ZK]ZK\YJ^[L\YJZWHZWHZWHZVG[VG]XI\WHZUFWRCUPAUPAVQBWRCYTEYTEYTEXSDXSDXSD
13389886      0xCC503E        rzip compressed data - version 89.67 (1263815251 bytes)
13514042      0xCE353A        StuffIt Deluxe Segment (data): fVcdTbdT`cS^aQ\_OSWGPVEJP?KQ@V\KW]LX^M`fUjn^lo_XZJBC3JK;QQAQO@TQBTPAUPASN?RM>UPATO@TO@UPATO@TO@TO@UPAVQBUPAUPAUPAVQBUPATPARO@SPA
13654843      0xD05B3B        HPACK archive data
13840991      0xD3325F        StuffIt Deluxe Segment (data): fVgiYfiYcfVbeUadT_bR\_O\_O_bRadT`cS^aQ\_OZ]M]_O`aQ_`P_`P^_O^^N^^N^^N__O``P`^OebSb_Pc`Qb`Q__O^_O`aQbcScdTcdT^_O[\LUVFTUEWWGXYIWZJ
14459717      0xDCA345        StuffIt Deluxe Segment (data): fV`aQYZJTUEWXHYZJUUESSCWWGYWHZWH\YJa^OeaRa\MUO@[TE]TF[RDXOAaXJ[RDRI;SJ<UL>UL>UL>VM?XOAXOAWN@TK>SJ=UL?WNAUL?RI<QH;TK>VM@WNATK>RI<
14532293      0xDDBEC5        StuffIt Deluxe Segment (data): fV_`PhiYacS[^NUYIW]Lem\[eTckZw}lyzjjgXRM>LE6NE7UL>UL>VM?YPBWN@VM?VM?WN@WN@VM?RI;PG9QH:SJ<TK=TK=UL>WN@UL>TK=UL>VM?VM?UL>TK=SJ<TK=
14908154      0xE37AFA        StuffIt Deluxe Segment (data): fVop`vwguvfpqamn^kl\ttdjgX_ZKZTE^WHb[Lb[L`YJ^WH`YJb[Ld]Nc\Mb[Lb[L`YJ_XIaZKc\Mf_PjcTe^Od]Nf_PaZKc]N^YJXSDYTE\WH\WHSO@TQBb_PspaecT
15451851      0xEBC6CB        rzip compressed data - version 90.73 (1432243550 bytes)
15844847      0xF1C5EF        VMware4 disk image
24952928      0x17CC060       StuffIt Deluxe Segment (data): fdbcaZ[YOPNPQO]^\`a_WXV[\Zefddec^_]OPNMNLXYW`a_mnlmnl\][YZXRSQCDB?@>DEC@A?BCADECCDB:;9897BCACDBEFDFGE675'(&./-<=;;:9;98<:9A?>B@?

```

```
binwalk picture3.bmp

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PC bitmap, Windows 3.x format,, 807 x 605 x 24

```

Extract picture2.bmp with 

```
binwalk -e picture2.bmp
```

Resulted in .sit file. Seems to be compressed with StuffIt. Tryied to decompress them with ```unstuff``` that could be find here:

```
wget http://mirror.sobukus.de/files/grimoire/z-archive/stuffit520.611linux-i386.tar.gz
```

Nothing.

Remembering text in 'Plan', the dash before DUEDILIGENCE was strange.

After using steghide on picture3.bmp with it:

```
./steghide --extract -sf picture3.bmp
```

Passphrase: DUEDILIGENCE

flag.txt was extracted.

## Flag

picoCTF{h1dd3n_1n_pLa1n_51GHT_18375919}
