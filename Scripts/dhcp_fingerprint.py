import sys 
def parse_dhcp_fingerprints(file_content):
    fingerprints_db = {}
    
    # Séparer les lignes
    lines = file_content.split('\n')
    
    # Ignorer la première ligne si c'est l'en-tête
    if lines[0].startswith('#fields'):
        lines = lines[1:]
    
    for line in lines:
        if not line.strip():
            continue  # ignorer les lignes vides
        
        # Séparer les champs par tabulation
        parts = line.split('\t')
        if len(parts) < 4:
            continue  # ignorer les lignes mal formatées
        
        dhcp_hash = parts[0]
        dhcp_fp = parts[1]
        device_name = parts[2]
        score = parts[3] if len(parts) > 3 else "0"
        
        # Créer une entrée dans la base de données
        fingerprints_db[dhcp_hash] = {
            'fingerprint': dhcp_fp,
            'device_name': device_name,
            'score': score
        }
    
    return fingerprints_db

# Fonction pour calculer la similarité (identique à la précédente)
def calculate_similarity(input_list, db_list):
    input_set = set(input_list.split(','))
    db_set = set(db_list.split(','))
    
    intersection = input_set & db_set
    union = input_set | db_set
    
    if not union:
        return 0
    return len(intersection) / len(union)

# Fonction principale adaptée au nouveau format
def find_best_match(input_fingerprint, fingerprints_db):
    results = []
    
    for entry_id, data in fingerprints_db.items():
        score = calculate_similarity(input_fingerprint, data['fingerprint'])
        if score > 0:  # Seulement si au moins un élément en commun
            results.append({
                'entry_id': entry_id,
                'device_name': data['device_name'],
                'fingerprint': data['fingerprint'],
                'original_score': data['score'],
                'similarity_score': score
            })
    
    # Trier par score de similarité décroissant
    results.sort(key=lambda x: x['similarity_score'], reverse=True)
    
    return results

# Exemple d'utilisation
if __name__ == "__main__":
    # Exemple de contenu de fichier (remplacez par votre vrai fichier)
    sample_file_content = """#fields	DHCP_hash	DHCP_FP	FingerBank_Device_name	Score
ac8b90de1120d9e3e2a68354458de76a	3,1,26,252,42,15,6,12	3-D Printer Manuf. MakerBot	80
3afe30cdf1653a66970ae9ae8443bdca	1,3,4,5,6,12,15,28,42	Juniper networks JUNOS	80
32ab58f29eea4ba05d5f5e60a1ce004c	1,3,6,28,15,12	Juniper networks JUNOS	80
0987f4adb4a2084d53e9750aecec8d8f	58,59,1,28,121,33,3,12,119,15,6,40,41,42	Printer or Scanner/Shandong New Beiyang Information Technology	87
722dcf1e1ff90c47a09071c81677ddb3	1,2,3,4,6,15,42,54,66,43	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87
602c9de54ffecb8ebdd2bad39e716fe3	1,3,28,15,6,44,69,70,42,12,4	Printer or Scanner/Toshiba Printer/Toshiba Multifunction Printer	87
3d2a90d3af74cebf3da76e44133bc00d	1,3,6,12,15,42,66,150	VoIP Device/Cisco VoIP/Cisco ATA 186	87
2eeb32e31e18f05313382cf0fdd7ff63	1,66,6,3,67,150,43	Switch and Wireless Controller/Cisco Switches/Cisco Catalyst 29xx	87
8e3a91485efa4616477bb99fbc298c98	1,28,3,58,59,6,15,78,79,44,46,69,116,66,67,12	Printer or Scanner/Xerox Printer	87
8f6a591a59fb8877590abf63d0ee50c6	1,15,3,6,44,46,47	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87
42e0f7989e43cdcb50278f1f2d07143b	1,3,58,59	Audio, Imaging or Video Equipment/Extron/Extron TouchLink Touchpanels	87
f4068dbb375c67cbda980359aca5e66b	1,3,4,23,67,66,43	Switch and Wireless Controller/HP ProCurve Switches/HP ProCurve 3500yl	87
9e385698593982f394d6fa03cfe5a32d	1,28,2,3,15,6,12,40,41,42,26,119	Operating System/Linux OS/RedHat/Fedora-based Linux	87
e5947bd5abba68eb9db9488fa26bc209	1,3,6,15	Xbox	50
fd01dc539b40bece18fc57dcfb8913e2	1,3,12,23,6,15	Printer or Scanner/Canon Printer	87
d4aa812a1594543e2abd4c5da75871c5	1,3,6,12,15,17,28,42	TP-Link Wireless LAN Router	50
b2c5826bc782ad9eb9c0708fca7e1d8d	1,3,6,12,15,28,33,44	Router, Access Point or Femtocell/Router/Belkin Wireless Router	87
355da6ef2659d25f2216a30876b58f76	1,3,6,15,119,95,252,44,46,47	Operating System/Apple OS	87
949651f5776c73dbc85494abe47292b2	1,3,6,15,33,44,46,47,121,249,43,60,212	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.2	87
2e5aeb37b05e28cce37c34a7c08047fb	1,28,2,3,15,6,12,4,7,23,26,43,50,51,54,55,60,72	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87
669ade68e57d61099c9509df171a7bfc	6,3,1,66,15,150	VoIP Device/Cisco VoIP/Cisco IP Phone	87
debfdee41829c71f0eae4102084388b6	1,28,160,66,3,4,42,2,6,15	VoIP Device/Polycom VoIP/Polycom SoundPoint IP/Polycom SoundPoint IP 450	87
6242c451d2b88abcd7ad6542a139396a	1,28,2,3,15,6,4,7,23,26,43,50,51,54,55,60,61,72	Router, Access Point or Femtocell/Router/Actiontec Wireless Router	87
e486de483631b0174ad9269dc691a43b	1,28,3,6,15,2,42,4,66	Video Conferencing/ClearOne/ClearOne Gentner Communications CONVERGE1212 CONVERGE880	87
621b08b9d8a440d8ba6aa806dfde784c	1,3,6,12,15,17,23,28,29,31,33,40,41,42,9,7,44,45,46,47,119	Operating System/Linux OS/SUSE Linux/Novell Desktop	87
7fc71e153da2cb21f71b2382a3dbbc46	1,28,3,6,12,15,53,54,51,58,59,69,44,60	Phone, Tablet or Wearable/Intermec Handheld	87
e2d67a71ce8cab6e22fe2957fceff66a	1,121,33,3,6,12,15,28,42,51,58,59,119	Operating System/Google OS/Android OS	87
038884bd199f72cd0d08c0622a76714f	54,51,6,1,3,15,120	Phone, Tablet or Wearable/Sharp Phone	73
d850cb4ba43a8f6c7223f12b3176ce70	1,28,3,43	Router, Access Point or Femtocell/Wireless Access Point/Cisco WAP	87
78b2b46b479fc6ae4cdf22e7d7564476	1,3,4,23	Switch and Wireless Controller/HP ProCurve Switches	87
7cdcd80d82a877dc612c064e293daddb	1,3,6,12,15,17,23,28,29,31,33,40,41,42	Operating System/Linux OS/Gentoo Linux	87
867919393063959017b7c6e5ec5dc1df	1,3,28,6	Operating System/Embedded OS	87
6bd0e16cb4c8efa02a4dd458203e482d	28,2,3,15,6,12	Audio, Imaging or Video Equipment/Video Equipment (Smart TV, Smart Players, etc.)/TiVo TV	87
2b1eda3fcf0d78fc996e820016aee191	1,28,2,3,15,6,12,40,41,42	Operating System/Linux OS/RedHat/Fedora-based Linux	87
43cf69a368e467e4fee0db9d9267db75	1,3,6,15,112,113,78,79,95	Operating System/Apple OS/Mac OS X or macOS/Mac OS X	87
ba4fd916c99fdbead39a9d20a96498ac	1,3,12,23,6,15,44,47	Printer or Scanner/Kyocera Printer	87
aa96be0f747678dcf452b470a57c7bc2	1,6,15,3,43	VoIP Device/UTStarcom F3000	87
f8de13b9447290186aac803305e52ada	1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,33,252,42	Operating System/Linux OS/Generic Linux	87
107cbc187d74a39373850219c3d11eb7	1,3,6,12,15,28,51,54,58,59	Printer or Scanner/Epson Printer	87
18b275583e6baddab2bd0086faa831e8	1,3,6,12,15,42,66,67,120	VoIP Device/Snom VoIP solutions	88
f6c12d0c767dc3d2ab547586e599e520	28,2,3,15,6,12,44,47	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.1,5.2	87
4509b96ba8bf6b08b755191604b668b4	1,15,3,6,44,46,47,31,33,43,252	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.0	87
2b684a60be52e5be48b7a34b6eb4612d	1,15,3,6,44,46,47,31,33,249,43,0,128,112	Operating System/Linux OS/Generic Linux	87
3bee5470ddbe9f28ad83eca41b5e28fa	1,28,2,3,15,6,119,12,44,47,26,121	Operating System/Linux OS/Ubuntu/Debian 5/Knoppix 6	87
d2b3a8865ca739a269023877cfd366ea	58,59,6,15,66,67,51,54,1,3	VoIP Device/Panasonic VoIP/Panasonic KX-UDS124CE SIP-DECT Base Station	87
f899139df5e1059396431415e770c6dd	100	Network Boot Agent/Novell Netware Client	87
5f3bd39caf77edcc702a5d631f07dc11	28,3,6,15	Router, Access Point or Femtocell/Wireless Access Point/Apple Airport WAP	87
129911f09a4f5e138545121f5a368af8	1,3,44,6,7,12,15,22,54,58,59,69,18,43,119,154	Printer or Scanner/HP Printer	87
fd16fc4460bf4c3a8ad5956732a78e4a	1,3,6,15,12,19	Operating System/Other OS/BeOS	87
014b9ca122c45656f0a9ebb06c94e43a	1,6,15,44,3,33,150,43	Router, Access Point or Femtocell/Wireless Access Point/Cisco WAP	87
ffddcdcdec6789737be00d00975fc647	191,157,144,128,66,160,7,54,42,15,6,4,3,2,1	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87
22cd9345fee014f118e82bfe54d6d791	1,28,160,3,4,42,2,6,15	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87
d672e0a975305da593e1ce57e1c51b47	1,2,3,5,6,11,12,13,15,16,17,18,43,54,60,67,128,129,130,131,132,133,134,135	Network Boot Agent/PXE	87
367d4f512a2fbc3872d0b80e5c4aa4d3	1,3,5,6,56,13,15,17,23,28,42,50,51,53,54,56,66,67	Samsung S8500	50
272ea7f0935b2249b477bea0ee4f323b	54,51,6,1,3,26,15,120	Operating System/Embedded OS/Java ME OS	73
5404e845092d0a378fc64f6002fcb1dc	12,6,15,1,3,28,120,119	Operating System/Symbian OS	73
5b29fedeee78722f7c33c410e5ed858f	1,28,3,6,15	Router, Access Point or Femtocell/Wireless Access Point/Apple Airport WAP	87
010697c6b9a31a8d07214b33d684d132	1,28,2,3,15,6,119,12,44,47,26,121,42,121,249,252,42	Operating System/Linux OS/Debian-based Linux/Ubuntu	87
7afa05f3fc307f5f8c4bba4c7ee79d9c	1,15,3,6,44,46,47,31,33,249,43,252,12	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.1,5.2	87
8b01e3677f4c44308702836d2076d309	1,3,6,44,46	Printer or Scanner/Konica Minolta Printer/Konica Minolta Multifunction Printer	87
27a5187bbde5434cd9e4c86bebd6ab3f	3,44,6,81,7,12,15,22,54,58,59,69,18,144	Printer or Scanner/HP Printer	87
d50cde9d4d71ac91fd5bb6456579520e	1,28,3,15,6,12	Operating System/BSD OS/OpenBSD	87
ddf291132ef293cf15d56bed92486710	1,2,3,6,15,42	VoIP Device/Uniden DTA VoIP Adapater	87
04e3da332c7abbf26b45f271ca061c87	1,3,4,6,12,15,28,42,43,66,67,60	Router, Access Point or Femtocell/Wireless Access Point/Cisco WAP	87
11220e9825147e9370dfee76fd66dcbd	1,3,4,23,67	Switch and Wireless Controller/HP ProCurve Switches	87
16cd952dd148aae113a4404febc79112	3,6,15,28,12,7,9,42,48,49	Operating System/Linux OS/Debian-based Linux	87
83c278194cb5848823b520b51a68c74e	15,3,6,44,46,47	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87
f497a090641680a5376b37dfd204041e	1,3,6,15,119,95,252,44,46,101	Operating System/Apple OS/Mac OS X or macOS/Mac OS X	87
175244f4a63bab1e6298d8ff2117b1b6	51,58,59,1,3,43,128,144,157,191,251	VoIP Device/Nortel VoIP/Nortel IP Phone	87
1ced839da3300cebd35daf8c0258f9a1	1,3,6,15,51,44	Operating System/Linux OS/Knoppix	87
34e78a4a3bd3753ae6cc5eb627e9b069	1,3,42,6,7,15,58,59,66,2,150,151,160,159	VoIP Device/Cisco VoIP/Cisco/Linksys SPA series IP Phone	87
9a1b2dfa7a72359da3e599ac4e3401a3	1,2,3,6,12,15,17,23,28,29,31,33,40,41,42,43	Audio, Imaging or Video Equipment/Set-top Box/Amino Aminet STB	87
3557e754da6b1d1035c756f340a03491	3,6,15	Router, Access Point or Femtocell/Router/Netgear Router	87
adbe45beda62792a3235121a2299aa1b	1,3,6,12,15,28,42,40,38,23,37,39,19,26	Tripplite UPS	50
b85358b64b735281bdd453cb615b7574	1,3,6,15,120,114,125	VoIP Device/Gigaset Communications	88
a0a5dc8660f695280a1bfd784e0687be	3,6,15,112,113,78,79,95	Operating System/Apple OS/Mac OS X or macOS/Mac OS X	87
0cbed995a5dd57cc6db7cdd5021f3d4e	1,3,6,15,7,44,51,54,58,59,12	Hardware Manufacturer/SEH COMPUTERTECHNIK GMBH	87
3deaf5c02c59cd64ddf8a1a3d5585f02	1,28,3,6,15,67,4,7	Router, Access Point or Femtocell/Wireless Access Point/Cisco WAP	87
0ec0bd7155b9b30a0be0e5bc805b4f83	1,28,2,3,15,6,12,44	Printer or Scanner/Kyocera Printer	87
63e7ba1aca91c4b1f2d09c3d3b40a227	1,3,15,6,43,77	Router, Access Point or Femtocell/Wireless Access Point/Compex WAP	87
9cf33ca200d694a9d98b7bf43be36477	1,28,43,3	VoIP Device/Siemens VoIP/Siemens optiPoint 410/420	87
41dc6d158afc1c42a443946e7c5bc858	1,28,2,3,15,6,119,12,44,47,26,121,42	Operating System/Linux OS/Ubuntu/Debian 5/Knoppix 6	87
831c0150db00761a2368b30052855166	1,3,6,15,27	Switch and Wireless Controller/3Com Switches	87
d2daf836647fd050dcbf4a12ac905ced	1,3,12,23,44,47	Router, Access Point or Femtocell/Router/Belkin Wireless Router	87
dcc13c02873a15852688a66acfe148ff	1,15,3,6,44,46,47,31,33,121,249,43,252	Operating System/Windows OS/Microsoft Windows Kernel 6.x	87
867875ff63401b4b3716b331e8e31ca6	1,3,6,15,42,44,46,47,69	Audio, Imaging or Video Equipment/Axis Communications	87
5a47450ff4d51e654277c712b0fe904c	1,3,6,12,15,17,23,28,29,31,33,40,41,42,43	Audio, Imaging or Video Equipment/Set-top Box/Amino Aminet STB	87
3cd8fe8073a13f9e62ebf5ac7b2b3e20	1,28,3,6,15,12	Router, Access Point or Femtocell/Wireless Access Point/Enterasys WAP/Enterasys HiPath Wireless Access Point	87
afb293ed416aa274f44982c10d15c81a	1,28,2,121,15,6,12,40,41,42,26,119,3	Operating System/Linux OS/RedHat/Fedora-based Linux/Fedora/Fedora 14 based distro	87
a8e9b00a2d9ada3572f9aad904e2b71b	1,3,28,58,59,6,15,78,79,44,46,69,12,81	Printer or Scanner/Xerox Printer	87
4ea216631fa7e5104c16c1b2a3acf6db	1,28,3,6	Internet of Things (IoT)/ROBE	87
787ba2fe027c895c8e43ba02ec792f5b	1,3,6,15,119,252	Operating System/Apple OS/iOS	87
e2c0be24560d78c5e599c2a9c9d0bbd2	203	Monitoring and Testing Device/HP iLO Agent	87
9ea90168dc0b34d865d58314dce28dd9	1,3,6,12,15,28,42,43,186,187,188,189,191,192	Router, Access Point or Femtocell/Wireless Access Point/Motorola WAP/Motorola AP	70
01cd1cec9c7265fa276735425b46040b	1,3,6,15,51	Audio, Imaging or Video Equipment/Video Equipment (Smart TV, Smart Players, etc.)/Sony Player	87
9c76088f636f25fb30dc360cb52fe951	1,3,12,6,15,112,113,78,79	Operating System/Apple OS/Mac OS X or macOS/Mac OS X	87
13de0d7fe765646d63fec88ac239ebab	1,3,6,12,15,17,23,28,29,31,33,40,41,42,9,7,200,44	Operating System/Linux OS/SUSE Linux/Novell Desktop	87
68b64930a2cc9598cddd02b189e39425	1,3,43,60	Network Boot Agent/Apple Netboot	87
0cdea89b70b8b89da04eeea4c788d5e2	1,3,6,15,119,252,67,52,13	Operating System/Apple OS/iOS	87
77aa0029a46cd5776ad43884e472a69f	1,28,2,3,15,6,119,12,44,47,26	Operating System/Linux OS/Debian-based Linux	87
84589f6332381c14eff21b7c556a2fac	1,2,3,4,6,15,28,33,42,43,44,58,59,100,101	Monitoring and Testing Device/HP iLO Agent	87
9e4b73a401b6bce0c88314359a63de11	3,1,6,15,121	Router, Access Point or Femtocell/Router/Belkin Wireless Router	87
225798e3e886f07556be5c65b9cc467a	1,3,6,28,33,51,58,59,121	Operating System/Google OS/Android OS	87
04df6d1a181ae47ffd57e8a2c1b25615	1,3,6,15,12	Audio, Imaging or Video Equipment/Video Equipment (Smart TV, Smart Players, etc.)/Roku TV	87
b93314bee1dc9768f4eb3e8bf2665375	1,2,3,4,6,15,42,54,7,160,66	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87
cd803682e26a1538a932d8996edb6fef	6,5,3,44,15	Router, Access Point or Femtocell/Wireless Access Point/Trendnet WAP/Trendnet Access Point	87
69217251b4b9028059acd8e6ae92d3eb	1,121,33,3,6,28,51,58,59	Operating System/Google OS/Android OS	87
8e57e0008d9327b8595f7ce0e088a606	1,3,23,6,15	Printer or Scanner/Konica Minolta Printer/Konica Minolta Multifunction Printer	87
3f6d8f8ed3c4c2cf7d20eed17bc753c3	1,28,160,43,3,4,42,2,6,15	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87
8e791b74d969cc605acdf456bf1e85fd	1,3,5,6,12,13,15,17,23,28,42,50,51,53,54,56,66,67	Operating System/Samsung Bada OS	87
1676d6f554617caac1abb4a4ebebe652	163,1,28,2,3,15,6,12	Barnes and Noble Nook (eReader)	50
838e83b569d89855fd46d981b017212c	15,3,6,44,46,47,43,77,252	Operating System/Windows OS/Microsoft Windows Kernel 4.x/Microsoft Windows Kernel 4.10	87
a67c8d836e10d87fb586f740f6172bda	1,3,6,12,15,28,44,46,47	Router, Access Point or Femtocell/Router/D-Link Wireless Router	87
d6ca7b1a041218a3924e9e399b41348b	1,3,6,12,15,28,60	Audio, Imaging or Video Equipment/IP Camera/TRENDnet Camera/TV-IP512P PoE Network IP Camera	87
68e4a15afd3fb5316e3d8ce096c8cc5a	1,3,44,6,7,12,15,22,54,58,59,69,18,144	Printer or Scanner/HP Printer	87
300a2cae8392e6ac86ebc4e2ceb26dc3	1,3,6,12,15,28,33,40,41,42,44,46,47	Router, Access Point or Femtocell/Router/D-Link Wireless Router	87
e8df7dec3079fb9d5d6bc4c3d6b60dc3	1,28,66,6,15,3,35,176	VoIP Device/Polycom VoIP/Unidentified Polycom	87
3c50b181450786b21ab49746fd20539c	1,3,6,15,112,113,78,79,95,252	Operating System/Apple OS	87
70fe2266821bd6ef88a7df58d27bd1d5	1,3,12,23,6,15,42,44,47	Printer or Scanner/Oki Printer	87
df4c316392c6b156ef8ac7be8dc4abb4	1,2,3,6,12,15,26,28,85,86,87,88,44,45,46,47	Printer or Scanner/Brother Printer	87
637856d94054cf3f58e63b6586cc9c92	1,15,3,6,44,46,47,43,77	Operating System/Windows OS/Microsoft Windows Kernel 4.x/Microsoft Windows Kernel 4.10	87
e68f35f2c0505f5eacf19174a83298c5	1,28,3,58,59,6,15,78,79,42,44,46,69,116,66,67,12	Printer or Scanner/Xerox Printer	87
de8a024a39d6d35253434f62010434cb	1,3,6,12,15,26,28,40,41,42	Router, Access Point or Femtocell/Wireless Access Point/Meraki WAP	87
2136dc24ca186a1ddc81c531d8c6b643	1,3,7,44,51,54,58,59,12,15,144,18	Printer or Scanner/HP Printer	87
9e4102a6d91aadc212eb70a09df6c7f6	1,28,66,6,15,3,35,43,128,131,144,157,188,191,205,219,223,232,247,251	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87
37fbbfb1847f9ba3874111cc086c72f7	43,60	Operating System/Apple OS	87
ad86ecec5a46870663fa3a93cd2dec2b	1,2,3,6,15,26,28,85,86,87,88,44,45,46,47,70,69,78,79,120	Printer or Scanner/Xerox Printer	73
853085f3e65a473b73c5c763d9dbe573	3,15,6	Gaming Console/Sony Gaming Console	87
8c2a2f1245fe6ff8d655fdb1e308fb40	1,6,3	Storage Device/Xyratex NAS	87
b51d42453654f74676b4ac2476a0b5c6	1,3,58,59,6	Audio, Imaging or Video Equipment/Extron/Extron TouchLink Touchpanels	87
843cd79833cbd0bab4364d36313c9404	1,3,6,15,7,44,51,54,58,59,12,69,42	Hardware Manufacturer/SEH COMPUTERTECHNIK GMBH	87
861b6d2fe8c210f5bc852cab4a9368ea	1,3,6,12,15,43,66,67,128,129,130,131,132,133,134,135	Router, Access Point or Femtocell/Wireless Access Point/Symbol WAP	87
5283b3c35007c4b7c3eb4689fff012b8	1,121,33,3,6,15,28,40,41,42,51,58,59,119	Printer or Scanner/Kyocera Printer	87
3143189b83e9b68a6b8c5b431b3cf232	1,3,6,12,15,17,28,42,234	Router, Access Point or Femtocell/Wireless Access Point/Sophos WAP/Sophos Astaro AP 10 WAP	87
96d5839d2e809b25dc901b1bde9c3076	1,28,3,6,15,67,4	Router, Access Point or Femtocell/Wireless Access Point/Cisco WAP	87
d58fb42e80976b2c9c742cf92a4268d6	1,3,6,7,12,15,18,23,26,44,46,51,54,58,59,78,79	Printer or Scanner/Xerox Printer	87
03d910e3b249da9edc37b9cf15357bb2	1,3,6,28	Nokia	50
5a84586ca504d23b62a212169f6f4695	1,3,6,12,15,28,33,44,121,249	Router, Access Point or Femtocell/Router/Netgear Router	87
0e4cdc35f47d95e419616635254f07e4	1,3,6,15,119,252,46,208,92	Operating System/Apple OS/iOS	87
4c6a52a4e1304b60730f975c8525a2c9	1,3,6,15,112,113,78,79,95,252,44,47	Operating System/Apple OS/Mac OS X or macOS/Mac OS X	87
2c499e8a4a29bad97dd9663a6525fc99	15,3,6,44,46,47,31,33,43,77	Operating System/Windows OS/Microsoft Windows Kernel 4.x/Microsoft Windows Kernel 4.90	87
dd9a8075579cd368364c122ee13c98e2	58,59,6,15,51,54,1,3	Audio, Imaging or Video Equipment/Video Equipment (Smart TV, Smart Players, etc.)/Panasonic TV	87
6813a4f31f28abb1d78f2d8931875a76	1,28,2,3,15,6,119,12,44,47,121	Storage Device/Iomega NAS/Iomega Backup Center	87
2976a79cb057283c6f898e1797c2523c	1,28,3,58,59,6,15,78,79,12,42,44,46,69,116,66,67	Printer or Scanner/Xerox Printer	87
55d26ff6ad9b1212a9ea31f327a8d1d3	1,3,6,12,15,66	VoIP Device/Siemens VoIP/Siemens optiPoint 150 S	87
ea3585d33770930772a2ba9b0b9d0f9c	1,33,3,6,15,28,51,58,59	Operating System/Google OS/Android OS	87
d3c55363ae47b6e81abc22fc204c6089	1,28,3,15,6,12,42,242,120,66,43	Video Conferencing/Tandberg	73
b07c79e6c947cf62a365a43718d23792	1,3,6,15,42,43,44,46,47,119	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87
d728867895490b748a2fba3ab66b9d87	1,28,3,6,15,42,43,176,66	VoIP Device/Avaya IP Phone	87
497964ad7847d67e06fb5bb997d2db90	1,2,3,6,12,15,28,33,42,43,120	VoIP Device/Siemens VoIP/Siemens OpenStage IP Phones	88
bd820cb5cbcff37b0d8ca723d8bc3a2c	1,3,6,12,15,28	Operating System/Linux OS/Embedded Linux 1,3,6,12,15,28	29
3c577f2c4f03e38a6152c7a1976ee350	1,121,33,3,6,12,15,28,40,41,42,51,58,59,119	Operating System/Linux OS/Gentoo Linux	87
f60dec4dee5e5c09b76c239a07ebaaec	1,3,6,44,15,46,47	Router, Access Point or Femtocell/Router/D-Link Wireless Router	87
111f7334ef11087006a58a26d6e03270	1,3,6,12,15,28,43	OpenSolaris	50
05d08339b04198d8228331691c40ecf9	1,3,42,4,6,7,12,26,44,51,54,58,59,190	Printer or Scanner/Lexmark Printer	87
6cd36214819db20d68f46faa667bc1a2	1,3,6,12,15,28,42,66,149,150	VoIP Device/Cisco VoIP/Cisco IP Phone	87
f1ba0d59313d14283f03355e7f841597	1,3,28,58,59,6,15,78,79,44,46,69,66,67,12,81	Printer or Scanner/Xerox Printer	87
3e957efc5a7bfc745fdf43ecad84e0de	1,15,3,6,44,46,47,31,33,249,43,252	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.1,5.2	87
578d94c00c0901b269591b1c33aba88a	1,3,7,6,15,66,69,43,176	VoIP Device/Avaya IP Phone	87
824386c9f248aeffe83da563ed7492ef	1,33,3,6,28,51,54,58,59	Operating System/Google OS/Chrome OS	87
c9b5b5d3dba39e931d52c213c716587a	1,3,15,6,12,35,66,150	VoIP Device/Cisco VoIP/Cisco IP Phone	87
56ab12683b84482929c62980fb8b7dc8	1,2,3,4,5,6,12,13,15,17,18,22,23,28,40,41,42,43,50,51,54,58,59,60,66,67,97,128,129,130,131,132,133,134,135	Network Boot Agent/PXE	87
6cc5e190bed3405319277c37ab9153f0	1,3,6,12,15,28,44,47,204	Printer or Scanner/Ricoh Printer/Ricoh Multifunction Printer	87
d2ce413f435924f47ed01e535057e9fc	3,6,12,15,17,23,28,29,31,33,40,41,42,9,7,200,44	Operating System/Linux OS/Generic Linux	87
eb7a42a7f407539ee163444f27cee1c5	1,3,6,66,15	VoIP Device/ZyXEL WiFi Phone	87
4d5c6faedf4b9ffc2ed3ab1cd308d4e0	1,3,7,44,51,54,58,59,12,144,18	Printer or Scanner/HP Printer	87
424ce1e74ec6573251253f086ac34992	1,3,12,44	Network Boot Agent/Generic Intel PXE	87
62d1bb67e19bb52e50ada87c9a126464	1,28,2,3,15,6,12,4,7,23,26,43,50,51,54,55,60,61	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87
92dd8e7a49f6389ada66769f173a9466	1,2,3,4,5,6,7,8,9,12,13,15,16,17,23,26,28,42,44,50,51,53,54,56,66,67	Samsung S8000	50
d4f62821afcb7ffd01bfd0377bddf21f	1,3,6,12,15,28,33,44,121	Router, Access Point or Femtocell/Router/Netgear Router	87
c6b7a51c6f3a3dbeafccfc6c97d8ec26	1,66,6,3,15,150,35	VoIP Device/Cisco VoIP/Cisco IP Phone	87
7ee5c304d7cdf2f5292391471218f15a	1,3,28,43,58,59	VoIP Device/Alcatel IP Phone/Alcatel IP Touch 8 Series Phones	87
e73551d71e9c7b90858cfd2ea6052d75	1,28,15,6,3,1	Audio, Imaging or Video Equipment/Matsushita or Panasonic	87
60dfcc8f2c99fd39d339bd0a54664f85	1,28,2,3,15,6,12,42,157	Video Conferencing/LifeSize Video Conferencing	87
d0ba5e90ca6678ef85128d3bec133e6b	252,3,42,15,6,1,12	Meego Netbook	50
945320123f752be1c2965ee054398587	116,252,67,28,59,58,15,6,119,81,44,46,47,42,70,3,78,79,69,1,66,2	Printer or Scanner/Xerox Printer	87
d47c0029a3bc5b69704274f726f91344	1,28,3,15,6,12,7,26,42,43,242	VoIP Device/Avaya IP Phone	87
4e36cd5ff87894ee7c113f3503d7c3f5	1,28,1,3,6,4	Router, Access Point or Femtocell/Router/Motorola Router	87
eccc5ed121dd81b1e4b059285dfab24f	1,15,3,6,44,46,47,31,33,121,249,43,200	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.1,5.2	87
81d55179434739fe2afce8f8d151a9ae	1,3,6,51,58,59	Physical Security/Paradox Card Access module	87
4118b41b9cc98b2f2c265d1afa02f227	1,121,3,6,12,15,28,33	Router, Access Point or Femtocell/Router/Netgear Router	87
d813a2681952b8936e5557fbb657490c	1,3,6,15,35,66,51,150	VoIP Device/Cisco VoIP/Cisco IP Phone	87
fa35d2826edab475ec3abcdd3cbeade7	1,28,3,66,4,42,2,6,15	VoIP Device/Polycom VoIP/Polycom SoundPoint IP/Polycom SoundPoint IP 301	87
baab9c26b706ff32008c489a79941ec2	1,28,3,6,15,33,42,2,43,120	VoIP Device/Siemens VoIP/Siemens optiPoint 410/420	88
c1ccaa8518ee1d16a033741e13c0a5a6	1,66,6,15,44,3,67,12,33,150,43	Router, Access Point or Femtocell/Wireless Access Point/Cisco WAP	87
f1ecff729cda55e5766e29d2dfe51f59	1,121,33,3,6,15,28,51,58,59	Operating System/Google OS/Android OS	87
6723774e7103a2667d834251ba14b647	1,121,33,3,6,12,15,26,28,42,51,54,58,59,119	Operating System/Linux OS/Gentoo Linux	87
6f87a73f46a2eb90b4d88c6113adcbdb	1,66,6,3,15,150,35,151	VoIP Device/Cisco VoIP/Cisco IP Phone	87
40dd7ac55fa1443cce034317cca84a9b	1,3,6,12,15,28,44,47	Printer or Scanner/Ricoh Printer/Ricoh Multifunction Printer	87
31b09a422c746c571a2e2d265f2f4488	1,28,3,26,12,15,6,40,41,87,85,86,44,45,46,47,42	Operating System/Linux OS/Suse Linux Enterprise Desktop 11	87
d59724879629e4ce3297500e7c64ace7	1,3,6,15,43,60	Router, Access Point or Femtocell/Wireless Access Point/Aruba WAP	87
47e366310b6659dcb4e996e8b3d18dba	1,2,3,15,6,12,44	Operating System/Apple OS	87
df9955f32817c420de302f6f06de0392	58,59,1,28,121,33,3,12,119,15,6,26,17,120	VoIP Device/Biamp devices	57
985f222d098b6410c0b3ba6e2a2722e5	3,6,15,112,113,78,79,95,252	Operating System/Apple OS/Mac OS X or macOS/Mac OS X	87
1584d6ba59295625acd49576398fe779	1,3,44,6,7,12,15,22,54,58,59,69,18,43,119	Printer or Scanner/HP Printer	87
f5f9a6b31fd722929d56d86fd3dbacbe	56,6,1,3,15	Phone, Tablet or Wearable/RIM BlackBerry/Blackberry Playbook	57
9bebf34634fc7f2f78ce2a9304ec8182	1,3,6,15,44,46,47,66,67	Operating System/Windows OS/Windows CE	87
f6fa648e67d8ae8da714c02580b6869a	1,28	Audio, Imaging or Video Equipment/Video Equipment (Smart TV, Smart Players, etc.)/Replay TV	87
e2b93a3aae1b04724ccd55566fadaf17	1,3,7,12,26,44,51,54,58,59	Printer or Scanner/Lexmark Printer	87
5df550dae88d999b9518585f8c3288a1	1,6,15,44,52	Switch and Wireless Controller/Cisco Switches/Cisco Catalyst 35xx	87
13e27e1c49faa3849ce21e5d2bb3cec4	1,3,6,12,15,17,43,60	Router, Access Point or Femtocell/Wireless Access Point/Aruba WAP	87
2b0c751c3a5e6d14a2021e532aceb5ab	6,1,3,12,44	Video Conferencing/Polycom Video Conferencing/Polycom ViewStation	87
86040c8bee83d14fb98fa56792ee758e	1,3,7,12,26,44,51,54,58,59,190	Printer or Scanner/Lexmark Printer	87
5b4a7b97f8bf07a8a802450467441dc8	6,3,1,15,66,67,13,44,43,58,59,42,2,12	Monitoring and Testing Device/APC/APC UPS	87
65c5b12e0859fca26c373b3cbfd3474d	1,3,6,12,15,28,42,40,38,23,37,44,39,19,26	Printer or Scanner/Lexmark Printer	87
dbce51eb241be624891557a8468e18bc	1,3,6,15,42,66,150	VoIP Device/Cisco VoIP/Cisco IP Phone	87
9fc8200cc5c5e2d9e3f30188fceb8efe	1,2,3,6,12,15,28,40,42	Operating System/Linux OS/FortiOS	87
08effb296fa6c73921e5858c513bd7b2	1,3,6,12,15,66,69,70,67	Router, Access Point or Femtocell/Router/D-Link Wireless Router	87
08d411df72086abf863b16ea30d54ebd	1,3,44,6,81,7,12,15,22,54,58,59,69,18,144	Printer or Scanner/HP Printer	87
f379132fcd0ada3ff4de988a4f85c77d	6,3,1,15,12,66,67,13,44	Printer or Scanner/HP Printer	87
1db973614a1ff05a5a2b440e158804b2	1,3,6,15,44,46,47,57	Operating System/Windows OS/Microsoft Windows Kernel 4.x/Microsoft Windows Kernel 4.10	87
bda34694562ebef7a797b3c390cdeaa1	1,28,2,3,15,6,12,44,47,26	Operating System/Linux OS/Debian-based Linux	87
f4581f7d7a41a03c947f854a08c35801	1,2,3,6,15,88,42,44,46,47	Router, Access Point or Femtocell/Router/2Wire(Pace) Residential Gateway Router	87
8e3844f06fb2b9bd5e0653d22457ea92	1,3,6,44,12,15,4,69,70,42	Printer or Scanner/Toshiba Printer/Toshiba Multifunction Printer	87
6c2922c236e88856ebbba3fe9107039d	3,1,6,15,12	Router, Access Point or Femtocell/Router/Netgear Router	87
2d91b548d2249039f50ae0d1d205a346	1,3,6,12,15,28,40,41,42	DD-WRT Router, or amazon kindle firmware 3.1	50
dbf9236ee5dfb605a1bf3f4d116c0a39	1,3,15,160,66,3,4,54,42,2,6,15	VoIP Device/Polycom VoIP/Polycom SoundStation IP/Polycom SoundStation IP 6000	87
edbb2d038cd2a610e7692549a124a277	1,3,42	Audio, Imaging or Video Equipment/IP Camera/Arecont Vision IP Camera	87
530c763acb1d6bf95887910cf33aef0c	1,3,43,44,46,47,6,33,121	Router, Access Point or Femtocell/Router/TP-Link Wireless LAN Router	87
df58f1953c9c5e0c80b57d6fe30982bf	3,1	Switch and Wireless Controller	87
c00f99b0ca5fc90f9f8e33eb5fa4a6e2	1,3,6,12,15,28,42	Operating System/Linux OS	29
60ecc8fe75db58a0fe838387964673c0	1,3,42,4,6,7,12,15,26,44,51,54,58,59,190	Printer or Scanner/Lexmark Printer	87
8b44420a54206a3071e2ee5a09222bf5	15,3,6,44,46,47,31,33,249,43	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.1,5.2	87
320375be93eb957c85d8dc6942db8e13	1,15,3,6,44,46,47,31,33,121,249,43,0,176,67	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.0	87
e36baf23a05a57ed641f6d09dbc259ea	1,3,6,15,28,54	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87
9f1803224f59d6aa7534ef6367f48c28	1,3,6,12,15,28,4,72	LG G2 F320	50
1cec4fdbf36172a65a83d32f678b28ec	1,3,6,12,15,17,23,28,29,31,33,40,41,42,66,72,150	VoIP Device/Nortel VoIP/Nortel IP Phone Model 1535	87
a7e55768537d4a56dbf0e0448974badf	1,3,6,42,43,66,159,160	VoIP Device/Aastra VoIP	87
636b95a6f9e9d23261bb9234ae1536d6	1,3,6,7,12,26,44,51,54,58,59,190	Printer or Scanner/HP Printer	87
07b959262356196585c4c7a14cfcda9b	6,3,1,15,66,67,13	Printer or Scanner/HP Printer	87
fd8609c983aa8f9c7fac268e5d96296e	1,3,42,4,6,7,12,15,26,51,54,58,59	Printer or Scanner/Lexmark Printer	87
5d33507e5c9467311defd7d335f49c52	1,3,15,242,4,54,42,2,6	VoIP Device/Polycom VoIP/Unidentified Polycom	87
2557990ec5b9521682949b6eac3548ee	6,3,1,15,66,67,13,12,44,2,42	Printer or Scanner/Brother Printer	87
893b08c86e01378e8b46f1d6e5dfc445	1,3,6,12,15,28,33,40,41,42,44,46,47,121,249	Router, Access Point or Femtocell/Router/D-Link Wireless Router	87
aea7e0d3532f34f2c6e6ca8680120aa1	1,121,33,3,6,12,15,26,28,51,54,58,59,119	Operating System/Google OS/Chrome OS	87
dd6c7cecda0c02f2c1310dedae28e1bf	1,3,6,12,15,44,46,47	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87
8564ddc922b1e41b5f60d7bde45609af	1,28,2,3,15,6,12,121,249,252,42	Operating System/Linux OS/Generic Linux	87
493b4e97b8c1b7f7762173ed8daf5962	1,3,6,15,33,44,46,47,121	Router, Access Point or Femtocell/Router/D-Link Wireless Router	87
41d306470a4c75917c0de92e3a3a8a70	1,15,3,6,44,46,47,31,33,121,249,43,0,112,98	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.1	87
f09395de9ee5a8fdfbc85d4796f2ea1c	1,3,12	Switch and Wireless Controller/HP ProCurve Switches/HP ProCurve 1800-8G	87
00867f74ee12151d546180e16fdd7ec6	1,3,6,43	Network Boot Agent/Etherboot/gPXE	87
380c4749944cdab6c6658ba25d1e450d	3,44,6,7,12,15,22,54,58,59,69,18,144	Printer or Scanner/HP Printer	87
eef44839a8809e3d073425da685b614c	1,28,2,121,3,15,6,12	Phone, Tablet or Wearable/Nokia Asha Phone	87
31c71ffa52efc989a291d00979e3f829	1,3,6,12,15,28,40,41,42,121	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87
b76c41cc46f78b685a94f33d225f5935	1,3,6,15,43,44,46,47,33,121,249	Operating System/Windows OS/Windows Phone OS/Windows Phone 8.0	87
15244a12b6803421f419d6ba81394165	1,3,6,12,15,28,33,121	Router, Access Point or Femtocell/Router/Netgear Router	87
a0c40127e0bce65e1d1302674e2b6882	54,51,58,59,1,3,6,15,28,139,2,42,66	VoIP Device/UniData IP Phone	87
51ab686b984b598e9f470417170bbb52	1,28,2,3,15,6,12,42	Operating System/Linux OS/Debian-based Linux	87
38819f7cad6a17a46e2f7dfb3b3b7b92	1,3,12,6,15,23,44,47	Printer or Scanner/Kyocera Printer	87
56769c78aa426d2e6bb2f3275190d086	1,3,7	Video Conferencing/Tandberg	87
e846318159bec141251c77040360cd5e	1,28,3,6,15,42,242	VoIP Device/Avaya IP Phone	87
8a1ae729e57846ea890423bd828300c9	1,3,43,44,46,47,6	Router, Access Point or Femtocell/Router/TP-Link Wireless LAN Router	87
73e2b4edc8b356a015fc95facf6d2ed9	1,3,6,15,112,113,78,79,95,44,47	Operating System/Apple OS/Mac OS X or macOS/Mac OS X	87
95429514c61ba503c9786e261aed0f2a	58,59,1,28,121,33,3,12,119,15,6,40,41,42,26,17,120,9,7,44,45,46,47	Datacenter Appliance/VMware vCenter Server Appliance	73
ea716e61d4b83e8576a03aff795848fb	3,22,23,1,24,33,35,6,15	Router, Access Point or Femtocell/Router/Quanta Microsystems Router	87
f38c33e4b7e75a4deeb7657a36fe1b72	3,7,44,51,54,58,59,12,15,144,18	Printer or Scanner/HP Printer	87
fb59744034c4dbdcd3f77e628debc0e4	1,3,6,12,15,28,42,44	Router, Access Point or Femtocell/Router/TP-Link Wireless LAN Router	87
2573cd779d0f285a1d1656dec76385ea	6,3,1,15,66,67,13,44	Epson Projectors	50
ba253caae2650981e0e26f5a7fce4ac3	12,6,15,1,3,28,120	Operating System/Symbian OS	73
a1a9b18508029b972ae5260c34e8d927	1,33,3,6,15,28,44,51,58,59,119	Phone, Tablet or Wearable/Generic Android/Motorola Android	87
50ef04cd4d16441d23c25c79b41871ef	1,28,3,15,6,12,44,81,78,79,116,2,42,58,59,69,119	Printer or Scanner/Xerox Printer	87
49e84f201db33403449de82b8021cffa	1,3,44,6,7,12,252,15,22,54,58,59,69,18,43,119,81,153,154	Printer or Scanner/HP Printer	87
395425ed01b43da819222fed634d7488	1,66,6,3,67	Switch and Wireless Controller/Cisco Switches/Cisco Catalyst 29xx	87
bea424f2edc51d994d82109dc076f73b	1,28,3,58,59,6,15,78,79,12,44,46,69,116,66,67	Printer or Scanner/Xerox Printer	87
854d6fae5ee42911677c739ee1734486	202	Monitoring and Testing Device/HP iLO Agent	87
a61d8912d8181cf0e6262023221d622a	1,3,6,15,35,66,150	VoIP Device/Cisco VoIP/Cisco IP Phone	87
779fe10a27d7e40626cdf4d0458cdf46	1,15,3,6,44,46,47,31,33,249,43,171,172	Operating System/Windows OS/Microsoft Windows XP for embedded devices	87
4843835e6dbba87fe1c19afc90753a05	1,3,4,23,67,66,43,6,15	Switch and Wireless Controller/HP ProCurve Switches	87
1216a5ede9ac49b35e27da89707b5885	1,28,2,3,15,6,12	Operating System/Linux OS/Debian-based Linux	87
3b23c752af2d3659c7623a343a32c818	1,2,3,6,12,15,26,28,88,44,45,46,47,70,69,78,79	Printer or Scanner/Xerox Printer	51
ac1ec361f34761f44885766efbb6ed77	1,3,6,15,28,12,7,9,42,48,49,137,211,212,213,214,219	Thin Client/Neoware e100 NeoLinux	87
a28c472812cbba32e26dfaadfab6d61b	1,3,6,12,15,23,28,29,31,33,40,41,42,44	Router, Access Point or Femtocell/Wireless Access Point/Buffalo WAP	87
0b21735e550202d6c98976710bf21990	1,3,6,7,12,15,18,23,26,44,46,51,54,58,59,78,79,81	Printer or Scanner	87
bb622ad6645ab4c9dc5e3f702674d8f1	1,3,6,12,51,58,59	Operating System/Embedded OS/Java ME OS	87
1eb60f5b63e7f9879ffd05eed8c814b0	1,3,6,12,15,28,50,33	Router, Access Point or Femtocell/Router/Belkin Wireless Router	87
1315b8ceeb55bdfdfa64f23c25da8a7c	1,3,6,15,28,33,40,41,42,51,58,59,119,121	Printer or Scanner/Kyocera Printer	87
15ba9bee40d90b3cc14b969d8999e7fd	1,3,6,12,15,17,26,28,40	Thin Client/Generic Thin Client	87
af49fb4d6460ababaa395b0f028faf6e	1,3,6,12,42,44,51,54,58,59,128,66,120,129,130,131,132,133,134,135,224,138,125,43,178,179	VoIP Device/Mitel IP Phone	88
e8d21fd0ba976a267649b3615c8bdd8f	1,3,6,15,44	Konica Minolta Multifunction Printer	50
6224015dcaea666d4187caaf4d99a5da	1,3,44,6,7,12,15,22,54,58,59,69,18,43	Printer or Scanner/HP Printer	87
b3608a3037645ab2af4ed8379ba48d85	1,15,3,6,44,46,47,31,33,121,249,43,195	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.0	87
bb969a90213dec8f4222379835716010	54,51,58,59,1,3,6,15,28	Audio, Imaging or Video Equipment/MagicJack Plus	87
c04c1c74934310b9dad50d91081fea65	1,3,6,15,33,43,44,46,47,121	Operating System/Windows OS	87
4ec01a78c3e69e723224dba5a9427cfa	1,3,6,12,15,28,33,121,249	Router, Access Point or Femtocell/Router/Netgear Router	87
e2451f86cfa6ea9831a5bcf44f159b18	1,3,4,6,12,42	Video Conferencing/VBrick Multimedia System	87
026c8aa8643ff6c92a7e5884ac4a2ef5	1,15,3,6,44,46,47,31,33,121,249,43,0,188,67	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.0	87
b232231c3a0346b5d70af36a15e60504	1,15,3,6,44,46,47,31,33,43,252,12	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.0	87
63f916c6aa2961b0f3a4020be9ca94bf	1,3,28,6,66,150	VoIP Device/2N TELEKOMUNIKACE Helios Phones VoIP	87
8d63fcbebb909bccbe9981f385015941	1,3,6,15,119,78,79,95,252	Operating System/Apple OS/iOS	87
281c0346c008127a6a570d87660684f0	1,3,6,42,43,2,66,159,160	VoIP Device/Aastra VoIP	87
d51a4c5fc1daabe2eca71d999d64af55	1,2,3,6,12,15,28,42,43,120	VoIP Device/Siemens VoIP/Siemens optiPoint WL2 Professional	88
9cdba26b8c0157b1cbba1c08125b3f13	1,15,3,6,44,46,47,31,33,121,249,43,0,80	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.1	87
6179df80b66fa84d295087eddd9868c2	1,3,6,12,15,23,28,29,31,33,40,41,42	Operating System/Linux OS/Generic Linux	87
11f40578a0f8c6fd2ebfa166d54cae75	1,28,160,66,43,3,4,42,2,6,15,7	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87
8940752701490eaf4ef9659d3d6a7f5c	1,2,3,4,7,6,15	Audio, Imaging or Video Equipment/Video Equipment (Smart TV, Smart Players, etc.)/Replay TV	87
d3b7141cc53de75612269673c8f94f66	1,33,3,6,12,15,28,51,58,59,119	Operating System/Google OS/Android OS	87
7dda7f93739a0e98b861feb94e37d570	1,28,3,43,128,131,144,157,188,191,205,219,223,232,247,251,58,59,66	VoIP Device/Nortel VoIP/Nortel IP Phone	87
d0bc4ce5154c75960c20edb2b4be0513	1,15,3,6,44,46,47,31,33,121,249,43,0,32,176,67	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.0	87
a5cc66ae8937a99c79d9d5327d56db0a	3,6,15,44,47	Printer or Scanner/Canon Printer	87
4867a5bf83a98e1f33f2b3898dec7ac1	1,28,2,3,15,6,12,43,191,186,187,188,189	Router, Access Point or Femtocell/Wireless Access Point/Motorola WAP/Motorola AP	70
148ea9f796f99288e3ef23bbb98f6051	15,3,6,44,46,47,43,77	Operating System/Windows OS/Microsoft Windows Kernel 4.x/Microsoft Windows Kernel 4.10	87
1dbd88f6451f4c547d471b70f8255c1e	1,15,3,6,44,46,47,31,33,121,249,43,0,112,64	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.0	87
55a8cd049c94b4f4bcd7b73709748522	1,121,33,3,6,28,42,51,58,59	Unknown Android	50
64e1f9134d3aa92cc59111b7346c7d3f	1,28,3,160,66,4,42,2,6,15,128,144,157,191	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87
263a7a64616a60145e3e802333d121a7	1,3,6,7,15,66,151,152	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87
6326e41f8894adb6c6654f1c0c9fad73	58,59,6,15,44,51,54,1,3	Printer or Scanner/Panasonic Printer/Panasonic MB2030CX	87
033da7bae38b52a64fddeda3d5d9878a	1,3,6,12,15,28,33,58,59	Gaming Console/Nintendo Gaming Console/Nintendo Wii	87
cce1837e21aebab3db1e3c860563755a	1,28,2,121,3,15,6,12,119	Storage Device/NAS4FREE NAS	87
b2dabbea6b57bb4bb81530b6649a42f7	1,33,3,6,15,28,44,51,58,59	Phone, Tablet or Wearable/Generic Android/Motorola Android	87
d0f328120ece80f978e2756aa885a344	1,15,3,6,44,46,47,31,33,121,249,43,0,64,112	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.0	87
d32f76558ab9c926497e4a50b4fc453e	1,15,3,6,44,46,47,31,33,121,249,43	Operating System/Windows OS	87
5eb6aef25b9d4f216c710112b2e569fb	1,3,6,12,15,17,23,28,29,31,33,40,41,42,66	VoIP Device/Nortel VoIP/Nortel IP Phone Model 1535	87
38ff29fbad10e9c818690b990d867626	1,28,3,6,15,33,42,2,43	VoIP Device/Siemens VoIP/Siemens optiPoint 410/420	87
29afe8d77f92419dcefc0e3261f3e0cc	1,2,3,6,12,15,26,28,85,86,87,88,44,45,46,47,70,69,78,79,120	Printer or Scanner/Xerox Printer	73
bd0a1fe09d674974abec8d6e713e0ae6	1,3,6,15,31,33,43,44,46,47,249	Router, Access Point or Femtocell/Router/Tenda Wireless Router	87
523dd6308c7241592b5ad602538e73dd	1,15,3,6,44,46,47,66	VoIP Device/Sipura VoIP Adaptor	87
4454918b1cf7185d9bc65c2be43f19c1	1,121,3,33,6,42	Router, Access Point or Femtocell/Router/MikroTik (RouterOS) Router	87
6e09934b78cd24eae24049edecd9e77c	1,28,2,3,15,6,119,12	Operating System/Linux OS/Debian-based Linux	87
41a3f18826eb2acfd89340484e0818f0	1,3,6,12,15,28,43,66,125	Operating System/Google OS/Android OS	87
d165bfca4168f21d39f9692a9d1014c9	1,3,6,12,15,120,242	Video Conferencing/Tandberg/Tandberg 1000	73
7640efd95cc17edd9c42701966512588	1,3,4,6,12,15,28,42,43,60	Router, Access Point or Femtocell/Wireless Access Point/Aruba WAP	87
9b83b0537ee0c5a458c05da8ff8df896	1,2,3,6,12,15,28,42,43,44	Router, Access Point or Femtocell/Wireless Access Point/Ruckus WAP	87
547183674e5075005cd3abc3d706de98	3,22,23,1,24,33,35,6,15,44,11	Printer or Scanner/Zebra Printer	87
0460db308a84c60805a1a587fc487503	1,28,3,160,66,4,42,2,6,15	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87	
7a9e0b8f3c95b14b48095ce29dfa4efa	1,3,6,12,15,17,23,28,29,31,33,40,41,42,9,7,44,45,46,47	Operating System/Linux OS/SUSE Linux/Novell Desktop	87	
0393b143018d7651322ce636aa1dd323	1,3,6,15,28,33,43,44,58,59	Monitoring and Testing Device/HP iLO Agent	87	
415aac222be7cd21bc2e4c12a9cc9776	1,28,3,15,6,12,44,78,79	Printer or Scanner/Xerox Printer	87	
d93b22f2a26ce324ef512858d6a331a4	1,3,6,12,15,28,40,41,42,119	Operating System/Linux OS/Generic Linux	87	
02130aa2e588de8e74f7317ad852272b	1,3,6,12,15,28,42,40,44,46	Printer or Scanner/Brother Printer	87	
75c1aaebcd1c703be383de5dd18289a0	1,3,6,15,44,46	Printer or Scanner/Konica Minolta Printer/Konica Minolta Multifunction Printer	87	
7615073d769798bac9000e3c2a60c8ba	1,3,6,7,12,15,17,43,60,66,67,175,203	Thin Client/Generic Thin Client	87	
2b6b05846a22bd9bfb6a987a98f2a170	54,59,83,101,114,61,57,52,50,49,80,89,51,59,255	Printer or Scanner/Lexmark Printer	87	
384fa6c0b7c34ac0dc469ea4c5f13f22	1,28,15,6,3	Internet of Things (IoT)/PHAST Electronics	87	
bf4f2f92032d27bc60cbd4d20e50777e	1,3,44,6,7,12,15,22,54,58,59,18,144	Printer or Scanner/HP Printer	87	
a625fa1de27a56a95b90ff58d99cb5bc	1,3,6,15,43,44,46,47	Router, Access Point or Femtocell/Router/Gemtek Wireless Router	87	
9be8f83c2048cfbcb2ad16fd95df5251	3,6,15,112,113,78,79,95,252,44,47	Operating System/Apple OS/Mac OS X or macOS/Mac OS X	87	
4bbdb01f3115faa8d3c88e0d41decf7c	1,6,54,69,42,50,4,3,51,12,116	Switch and Wireless Controller/3Com Switches/3Com 4400 SE Switch	87	
f636345cea080f1fb510e7c3a69f6e55	1,28,1,3	VoIP Device/Nortel VoIP/Nortel IP Phone	87	
6ee76da2855a5dd932de9a278c47a103	1,15,3,6,44,46,47,31,33,121,249,43,0,168,112,64	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.0	87	
1c7900b822a4cf67f1534717b24673f9	1,3,6,15,28,33,51,58,59,121	Samsung Android	50	
843b28c5f7a3056e80f1c940cb440c14	1,28,3,15,6,12,2,42,48,161,162,184,185,163,164,188,189,181,182,190,186,187	Thin Client/Wyse Technology Thin Client	87	
8dee8bbae755b7118a2f10045e5667f4	1,3,6,12,15,28,40,41,42,44,46,47	Router, Access Point or Femtocell/Router/D-Link Wireless Router	87	
1ab731fa44876965da26f35061b1daa1	1,3,6,12,15,28,44,46,47,33,249	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.0	87	
1ebed1f7c89fd0125c2a69ec1c309fcb	1,3,6,44,46,47,12,15,17,23,28,29,31,33	Router, Access Point or Femtocell/Router/D-Link Wireless Router	87	
2c36908444b6672be938e5b516fe473e	1,3,5,6,32,13,15,17,23,28,42,50,51,53,54,56,66,67	Samsung S8500	50	
e34acfd6b8b9699b3401b540c5b6b1e8	1,3,6,15,44,46,47,137,215	Thin Client/Neoware Capio Windows CE	87	
0efefd37ad783cd12af365e0f182c24f	1,66,6,15,44,3,67,33,150,43	Router, Access Point or Femtocell/Wireless Access Point/Cisco WAP	87	
3aa3d309498e0b8911bee164a739f391	1,3,43,44,46,47,6,33,121,249	Router, Access Point or Femtocell/Router/TP-Link Wireless LAN Router	87	
67b79680e88a63dd139d11830c7425ce	1,3,6,15,28,33	Operating System/Other OS/OS/2 Warp	39	
ef94aa50665b8e8f810edffc58632c64	1,3,28,6,15,44,46,69,12,81	Printer or Scanner/Xerox Printer	87	
96f153db323a02faaeabd4b69d0691fd	1,3,6,12,15,28,44	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87	
8d144bc30f7296d23b07d843c3dae19f	1,3,6,12,15,28,44,33,249	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87	
1a17e1cea20836ead55174c2acbd3b68	1,28,3,43,128,131,144,157,188,191,205,219,223,224,227,230,232,235,238,241,244,247,249,251,254,58,59,66,6,15	VoIP Device/Nortel VoIP/Nortel IP Phone	87	
e034c70ba2561e846a90e3dbd05a3b39	1,3	Operating System/Windows OS	87	
85bed46a040f83911d1688fc20ad338f	1,3,6,12,15,4,43,44,60,42,28	Router, Access Point or Femtocell/Wireless Access Point/Aruba WAP	87	
30cbdd104805d746d915e20e6a07bece	1,28,2,3,15,6,12,43	Router, Access Point or Femtocell/Wireless Access Point/HP Procurve WAP/HP ProCurve Access Point	87	
5cadd2a4a15266440d75ba27a9ea26a6	6,3,1,15,66,67,13,44,12	HP Printer	50	
1631725c14cf670618ef741c592cfb5e	1,3,6,15,33,44,46,47,121,249,43	Router, Access Point or Femtocell/Router/D-Link Wireless Router	87	
6e74be03487c3a9154c0a05e2be8dc82	1,121,33,3,6,15,28,51,58,59,119	Operating System/Google OS/Android OS	87	
6f74bae5cad31087fa5e3522139c89b0	1,3,28,6,12,15,26,42,242,120	Video Conferencing/Tandberg	73	
500286974a37eb5e9f499ae84eda5e9d	1,3,42,6,7,15,58,59,44,66,150,151	VoIP Device/Cisco VoIP/Cisco/Linksys SPA series IP Phone	87	
29c9e3acee49c51b938ca0b43fe1019d	1,3,4,23,67,66	Switch and Wireless Controller/HP ProCurve Switches	87	
61f3da60e6734e3926c4700b4a6ca502	6,3,1,15,66,67,13,44,12,81	Printer or Scanner/HP Printer	87	
eced511960251a430afcf15aaa412d3d	3,6,12,15,17,23,28,29,31,33,40,41,42,119	Operating System/Linux OS/Generic Linux	87	
7daf9f6592561d1767bfdc7d0383aab7	1,3,6,15,28,12,7,9,42,48,49	Audio, Imaging or Video Equipment/Video Equipment (Smart TV, Smart Players, etc.)/Sony TV	87	
46ee5f48a1c1b98456d7c54c5c678f96	78,79	Network Boot Agent/Novell Netware Client	87	
c0cbec608fde77b1ca424a816ac0f769	1,3,6,7,12,15,28,40,41,42,225,226,227,228,229,230,231	Router, Access Point or Femtocell/Wireless Access Point/Aerohive WAP	87	
fb068f7c1f14fabeb2ee04a17b9b7162	6,3,1,15,66,67,13,12,44	Printer or Scanner/Brother Printer	87	
36f3aa371ad6653edb6ee7c0459becd4	1,3,6,15,28,12,7,9,42,48,49,26	Network Boot Agent/Anaconda (RedHat) Installer	87	
9d85cd241c5dbc63dca980e5993c4e15	1,28,2,3,15,6,12,121,249,33,252,42	Operating System/Linux OS/Debian-based Linux	87	
8db89aa8a5764f4ac90ec576a13edd0b	1,3,43,54,60,67,128,129,130,131,132,133,134,135	Network Boot Agent/PXE	87	
b058c79c8f3a6bd557fc254d78fa9e11	1,121,249,3,6,12,15,28,33,43	N300 Wireless Router	50	
49d8b4d4301a19d48bd14e062bdef215	1,3,6,12,15,17,28	Thin Client/Generic Thin Client	87	
f8daa2dd03fec4845614f55a72dee9ba	1,3,6,15,44,46,47,31,33,43	VoIP Device/Clipcomm IP Phone	87	
7dd9f4e6bd7823eced45d49e6991915d	1,28,3,15,6,12,44	Router, Access Point or Femtocell/Wireless Access Point/Bluesocket WAP/Bluesocket BSC	87	
7186ad52211b3197376a60ccd49fef22	1,2,3,4,6,15,42,54,160,66,43	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87	
b5cd0b6b9dd7d6d116d93fe9436ff73c	1,3,6,7,15,66,151,152,43,128,129,130	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87	
7577c2c127ef294ee6df8f167ab02fd6	1,28,3,6,15,44	Router, Access Point or Femtocell/Wireless Access Point/Cisco WAP	87	
649d32d25b1310e1112b2b5d3befa13a	1,3,58,59,6,15	Audio, Imaging or Video Equipment/Extron/Extron TouchLink Touchpanels	87	
b483e62383e65a05bec84efa7ceb69d6	1,3,6,12,15,28,44,212	Router, Access Point or Femtocell/Router/Quanta Microsystems Router	87	
f5fd0ec3afebf24060f19db6e5aa0372	1,28,3,43,128,131,144,157,188,191,205,219,223,232,247,251,58,59	VoIP Device/Nortel VoIP/Nortel IP Phone	87	
2e54a7a0f24b40bf6eb4c06ad62ca919	1,2,3,4,5,6,11,12,13,15,16,17,18,22,23,28,40,41,42,43,50,51,54,58,59,60,66,67,128,129,130,131,132,133,134,135	Network Boot Agent/PXE	87	
535152e93ebc04f7306f95729a6d23ae	2,3,6	Xbox 360	50	
95509399a82c281da7319b7cdc3d4c01	3,6,15,112,113,78,79,95,44,47	Operating System/Apple OS/Mac OS X or macOS/Mac OS X	87	
8a43225bde8a77248b458ad4e4e00c9f	58,59,1,28,121,33,3,12,119,15,6,40,41,42,26,17,120,9,7,44,45,47	Datacenter Appliance/VMware vCenter Server Appliance	73	
904f0dadc3cf925103e67f571719e8aa	1,28,3,43,44,46,47,6	Router, Access Point or Femtocell/Router/TP-Link Wireless LAN Router	87	
d1741146dfa778102c2efb5617360b50	1,3,6,12,15,28,42,125	Samsung SMART-TV	50	
12e32964a4a9996245076255e1926f30	1,3,5,6,12,15,44,46,47,155,156,157,158,159,160,161,162,163,164,165,166,167,168,186,187	Audio, Imaging or Video Equipment/IP Camera/Tattile IP Camera	87	
f38236d012acba5b3be983cc9857cd16	66,160,7,54,42,15,6,4,3,2,1	VoIP Device/Spectralink	87	
31acb722c634a5eb878de548a21dcee9	1,3,6,15,33,42,44,45,46,47,69,70,71,74,78,79	Operating System/Apple OS/Mac OS/Mac OS 9	87	
2ebe77e577b2f394569fe1db28c40713	1,3,6,12,15,42,43	VoIP Device/Mediatrix VoIP Adapter	94	
236e83df37a3c463a7972c55cef0ddb1	1,3,6,120	Operating System/Embedded OS/Java ME OS	73	
9d18268b75fcab6f49a0c995900a19b0	1,15,3,6,44,46,47,31,33,121,249,43,0,192,176,112	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.1	87	
ec52c950dd503bf12edb385498b6aaa7	1,3,6,15,119,95,252,44,46	Operating System/Apple OS	87	
5ef958528b148b160e7f6935d78236d6	1,3,6,7,12,15,28,40,41,42,225,226,227,228	Router, Access Point or Femtocell/Wireless Access Point/Aerohive WAP	87	
2d38986fceb3356eedac7d267b43b9c6	1,3,6,42,12,15,31,33,43	Point of Sale Device/PCS Revenue Control Systems	87	
b2155371e8c2f112e4a530964ab850db	50,1,3,12,15,51,58,59,6,42,69,70	Projector/NEC Projectors	87	
52417472744907ea79ecbadbafe678cc	1,3,6,15,119,112,113,78,79,95,252	Operating System/Apple OS/Mac OS X or macOS/Mac OS X	87	
b7e0e3c345907e90833741b4b4794da0	58,59,1,28,121,33,3,12,119,15,6,40,41,42,26	Operating System/Linux OS/Gentoo Linux	87	
53396bad1f2b8c1b10f73bf5e36c2f40	1,2,3,6,12,15,28,42,43,66,120,125	VoIP Device/Grandstream VoIP	88	
e1d2a7161f861f3629e6e2b233d7409b	6,3,1,15,66,67,13,43,58,59,42,2,12	Monitoring and Testing Device/APC/APC UPS	87	
1782b667684970c18a491f29cbfcc688	1,42,4,6,11,3	Datacenter Appliance/Precision time and frequency reference system	87	
a08c7b70414fc797485298dbc9e150ef	1,15,3,6,44,46,47,31,33,249,43	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.1,5.2	87	
0e7e247572fbe0349e930aea480fb6ae	1,33,3,6,15,28,51,58,59,119	Operating System/Google OS/Android OS	87	
abb25c84fe73fa60eaca2516e14e142f	1,28,3,15,6,12,44,78,79,2,42	Printer or Scanner/Xerox Printer	87	
e8dd61058f9de98d0cd0da9ae1946da0	1,3,6,15,33,43,44,46,47,121,249	Router, Access Point or Femtocell/Router/TP-Link Wireless LAN Router	87	
2d384c642fe2a6388ba2e1b22cd21d5f	1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,33,42	Operating System/Linux OS/Debian-based Linux	87	
2f16c3781ff976d98eff96861c1215a8	1,3,6,12,15,17,28,40,41,42	Nokia	50	
372295443d05372967f2a18a29a0fc76	1,28,1,3,43,128,131,144,157,188,191,205,219,223,232,247,251,58,59	VoIP Device/Nortel VoIP/Nortel IP Phone	87	
d5174b480183ef8d99c37894f0d1ad15	85,86	Network Boot Agent/Novell Netware Client	87	
7efd10f3fdc450d1d16e76864cb3fa7c	1,3,15,6	Playstation 2	50	
356c0947a2a7d0b1523bd9124cabb900	1,15,3,44,46,47,6	Operating System/Windows OS/Microsoft Windows Kernel 4.x/Microsoft Windows Kernel 4.0	87	
87003bdce67c065b13e729f4caa7748d	1,3,6,12,15,28,66	VoIP Device/Grandstream VoIP/GrandStream HandyTone 503 ATA	87	
a1e8259c942611cc3db8f280a7db3f9b	1,28,2,3,15,6,119,12,44,47,26,121,42,121,249,33,252,42	Operating System/Linux OS/Debian-based Linux	87	
f6f4abef1302d62686219ea250393591	1,2,4,3,12,6,15,44,43,161,162,184,185,186,192,187,181,182,188,190	Thin Client/Wyse Technology Thin Client	87	
2e7bbb9d24a3d81f92620585f72068fd	1,2,3,6,12,15,17,23,28,29,31,33,40,41,42,43,72	Audio, Imaging or Video Equipment/Video Equipment (Smart TV, Smart Players, etc.)/Amino	87	
99b18e7cddac662b5a73b659201a8bab	1,3,12,43,17,128,129,130,150	Network Boot Agent/Etherboot/gPXE	87	
f712b8444d11ba600c6edf735a388ae8	1,3,6,15,42,66,51,150	VoIP Device/Cisco VoIP/Cisco IP Phone	87	
8b6ddb93a1ab882d04b88de876510b3e	1,28,2,3,15,6,12,4,7,23,26,43,50,51,54,55,60,61,72	Router, Access Point or Femtocell/Router/Gemtek Wireless Router	87	
9642a934b07f3c535142409d5737f25c	1,28,2,3,15,6,43	Router, Access Point or Femtocell/Wireless Access Point/Aruba WAP	87	
ce98151e46bdddec5ad01bc2cea4f1ef	1,3,6,15,119,95,252,44,46,47,101	Operating System/Apple OS	87	
6c9f13601fcd214fd321a32b9cbe2243	6,3,1,15,66,67,13,44,12,43,58,59,42,2	Monitoring and Testing Device/APC/APC-Schneider Uninterruptible Power Supply	87	
8ee1243f3c15e72fb1b135f896eb1f39	1,2,3,5,6,12,15,19,28,33,40,41,64,65	Operating System/Other OS/Solaris/Solaris 8 (SunOS 5.8)	87	
d36ccb241c1fed5d812c1feedaa75989	1,28,3	VoIP Device/Nortel VoIP/Nortel IP Phone	87	
056da8dd4360c7151019a5bcf27adf23	54,51,58,59,1,3,6,15,28,139	VoIP Device/UniData IP Phone	87	
5d0c9f08551fd4e4072640216c5b9864	1,3,6,12,42,44,51,54,58,59,128,66,120,129,130,131,132,133,134,135,224,138,125,43	VoIP Device/Mitel IP Phone	88	
9b3c4adefb5dd797173e770db49a3cb6	1,28,3,15,6,12,81,44,46,78,79,116,66,67,2,69,42,58,59,119,252	Printer or Scanner/Xerox Printer	87	
f66d524cc520c65283d627532514b07c	1,3,6,15,44,46,47	Operating System/Windows OS/Windows Phone OS	83	
ff6f66931e4983c0c53c2fcd422c72e1	1,66,6,15,44,3,67,12,33,150,43,125	Router, Access Point or Femtocell/Wireless Access Point/Cisco WAP	87	
95f55b3287ead1a4a889f6bcba94ac1d	1,3,28,58,59,6,15,78,79,44,46,69,66,67,12	Printer or Scanner/Xerox Printer	87	
47bd43caed4860dfc81383295818371a	1,3,6,10,12,14,15,28,40,41,42,87	Router, Access Point or Femtocell/Router/Zioncom Wireless Router	87	
f18cdf136219402fd37afcb7b33d3117	1,28,66,6,15,3,35,150	VoIP Device/Cisco VoIP/Cisco IP Phone	87	
3ef815416f775098fe977004015c6193	85	Network Boot Agent/Novell Netware Client	87	
43ffcbaa51f7497e90bf1e34dfa96f35	1,3,6,15,12,44	Video Conferencing/Polycom Video Conferencing/Polycom VSX 3000	87	
1babbc65645e99ae4d6714c74f9043d9	1,121,33,3,28,51,58,59	HTC Android	50	
8c648a3a5ff9aa4fbc1371f6eb6018d6	3,1,15,44,12	Printer or Scanner/HP Printer	87	
eea0590f4e15ae33800a86a5c054da18	60,43	Operating System/Apple OS/Mac OS X or macOS/Mac OS X	87	
c84495c51422c3c79d4fa0b1d32e6dd3	3,1,6,15	Router, Access Point or Femtocell/Router/Netgear Router	87	
80708b6d63237b86b49b88873508f400	1,3,15,6,44,46,47	Operating System/Windows OS/Microsoft Windows Kernel 4.x/Microsoft Windows Kernel 4.0	87	
412a88ade3f2a0c592afee514fe182cf	1,28,3,121,26,12,15,119,6,40,41,87,85,86,44,45,46,47,42,121,249,33,252,42	Operating System/Linux OS/Debian-based Linux	87	
f317d57d5822b8c840b606bda3148498	1,3,6,12,15,26,28,40,41,42,43	VoIP Device/NetCODEC Co VoIP	87	
5128f4c4661acd4d27dff1ab26cd4f08	1,15,3,6,44,46,47,31,33,43,77	Operating System/Windows OS/Microsoft Windows Kernel 4.x/Microsoft Windows Kernel 4.90	87	
bf69b863a78c82f19c9536879c517e86	6,3,1,15,12,42	Samsung Android	50	
d9bc916ae5f33fd9fc337c704061c55a	1,3,12,43	Network Boot Agent/Etherboot/Sun Blade 100	87	
bcdcadd6ba99dde710b1cc24ff0aebb6	58,59,1,28,121,33,3,12,119,15,6,40,41,42,26,17,120	VoIP Device/Biamp devices	57	
82ea225d3d3c9dd3a4801f92d2bb25a1	1,3,6,15,7,44,51,54,58,59,12,69	Hardware Manufacturer/SEH COMPUTERTECHNIK GMBH	87	
6384bfdfdcea889294dea8e37a2a8d9a	1,3,6,12,15,17,23,28,29,31,33,40,41,42,44	Storage Device/Synology NAS	87	
6035b6dcb4637d7c32d735255ee36e91	1,3,15,6,44	Printer or Scanner/Kyocera Printer	87	
1b6e1dc8e520125cf3c0cb192302846f	1,2,3,6,12,15,28,42,43,66,125	VoIP Device/Grandstream VoIP	87	
4857fe0b7f178863b502a39de6f861af	1,28,160,66,43,3,4,42,2,6,15	VoIP Device/Polycom VoIP/Polycom Conference IP Phone	87	
560ecc1dc513b437a62e473db0f230e0	3,6	Gaming Console/Microsoft Gaming Console/Xbox	87	
120c61da395411f35eb418525fbbfc49	1,28,156,4,3,66,42	VoIP Device/ShoreTel IP Phone	87	
fb7612836cf15b77145b541eef4bfc4d	1,3,42,6,7,15,58,59,44,66	VoIP Device/Sipura VoIP Adaptor	87	
610d451bb13b2767fbe65de65f870a18	1,6,15,44,3,33	Switch and Wireless Controller/Cisco Switches/Cisco Catalyst 35xx	87	
7ecb676302cd740699e046de33687302	1,15,3,6,44,46,47,31,33,121,249,43,0,176,112	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.1	87	
070c3cf1a676ffe467159f3cb75f8184	1,150,3,6,15,35,66	Operating System/Google OS/Android OS	87	
37e151d43203def5aa5946fb049df32f	1,3,4,6,12,15,17,23,28,29,31,33,40,41,42	Audio, Imaging or Video Equipment/IP Camera/ACTi Corporation IP Camera	87	
90cb86802a18db0c49a58b58c63edef0	1,15,3,6,44,46,47,1,3,6,15,44,46,47	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87	
09ee4037bb4e6dfd4a167c2938e19364	1,3,42,6,7,15,58,59,44,66,150,2,151	VoIP Device/Cisco VoIP/Cisco/Linksys SPA series IP Phone	87	
4d4ce239e75304e47fecd82c48801fcd	1,121,3,6,12,15,28,33,43	Router, Access Point or Femtocell/Router/Netgear Router	87	
41bd65643374639d0a9cbeb920bba2de	6,3,1	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87	
e4b4e1563f0179ce850f54919278966e	1,3,6,15,51,58,59,255	Router, Access Point or Femtocell/Router/Freebox Wireless Router	87	
60189fa092724f0650e7d1a551d7d177	6,3,1,15,44,12	Printer or Scanner/HP Printer	87	
e3031186cde5a9c2abf3cd19dce5d625	1,33,3,6,28,51,58,59	Operating System/Google OS/Android OS	87	
ea2154e1a4be1ba8cc862d49ae188adf	1,121,33,3,6,12,15,28,51,58,59,119	Operating System/Google OS/Android OS	87	
a287a44cb2c343f196e0daed069d734f	1,3,6,58,59,44,46,47	Printer or Scanner/Tally Printer	87	
f52dbb73a7fd6cb178be99c466c2aed8	1,28,1,3,6,42,66	VoIP Device/Aastra VoIP	87	
ef169c6aa735f58759b8ad48b813f47e	1,3,3,5,6,11,12,13,15,16,17,18,43,54,60,67,128,129,130,131,132,133,134,135	Network Boot Agent/PXE	87	
607caf801b644c3bd922db0e9865138e	1,3,4,6,15	Internet of Things (IoT)/Alps Electric	87	
1319fb44b0613dc4ce822c4357b47044	1,3,42,6,7,15,58,59,66	VoIP Device/Linksys PAP VoIP	87	
750e824b315765490e73cf8adf96db83	1,121,33,3,6,12,15,26,28,51,54,58,59,119,252	Operating System/Google OS/Chrome OS	87	
f49a8ea3c9d6a04f4c2f523c7ff6d380	1,121,33,3,6,15,28,44,51,58,59,119	Phone, Tablet or Wearable/Generic Android/Motorola Android	87	
5026b355656f9ce34620b751b27301e8	1,15,3,6,44,46,47,31,33,121,249,252,43	Operating System/Windows OS	87	
1f5e2ddd680d2a6b37b33ef295d6718b	1,15,3,6,44,46,47,31,33,43	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.0	87	
c0ba1956c8a39663bbca1a96eb391699	1,28,3,15,6,12,44,78,79,66,67	Printer or Scanner/Xerox Printer	87	
98a6a3042aeae3007a833ba32bb62b94	1,28,6,5,3,44,15	Router, Access Point or Femtocell/Wireless Access Point/Trendnet WAP/Trendnet Access Point	87	
f6f9310f8088ea378b7e3cdba3fb5c75	1,28,3,99,43,128,131,144,157,188,191,205,219,223,224,227,230,232,235,238,241,244,247,249,251,254,58,59,66,6,15	VoIP Device/Nortel VoIP/Nortel IP Phone	87	
71f173e75832a07b526c39f9ee79093e	1,3,6,15,70,69	Point of Sale Device/Moneris HiSpeed 3100IP	87	
5dd6695066a733b15c14e7727e0504e4	1,6,15,44,3,7,33,150,43	Router, Access Point or Femtocell/Wireless Access Point/Cisco WAP	87	
a3af1cfc7f3d84757bfd89502dc842ac	1,3,4,42,6,7,12,15,26,44,51,54,58,59,190	Printer or Scanner/Lexmark Printer	87	
179e34c753bf3c742c07e9d8d22c6ece	1,3,121,6,12,15,28,50,33	Router, Access Point or Femtocell/Router/Belkin Wireless Router	87	
a8342db66dcab3209f1b5bb48d40c78d	1,28,3,43,128,131,144,157,188,191,205,219,223,232,247,251,58,59,66,6,15	VoIP Device/Nortel VoIP/Nortel IP Phone	87	
b65635778cde45b83e18c21ad7efdbee	3,6,26,28,58,59	Gaming Console/Nintendo Gaming Console/Nintendo Gamecube	87	
6a3b43006c293765119851f8fb24b10c	1,3,6,15,44,47	Printer or Scanner/Canon Printer	87	
ea5dbe3d3b68c710bb45fecd0484e42c	15,3,6,44,46,47,31,33,43	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.0	87	
7e1142cabda50c38346a8fd02e6d091b	78,79,85	Network Boot Agent/Novell Netware Client	87	
501c3e5efb01269235a0218415bbcd61	1,33,3,6,15,26,28,51,58,59	Operating System/Google OS/Android OS	87	
8ebfc38441463ae19afd0760e614f471	15,3,6,44,46,47,31,33,43,252	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.0	87	
d81ebf5cd834bfbe57d8618bcd1c46e6	6,1,3,12,44,15	Video Conferencing/Polycom Video Conferencing/Polycom ViewStation	87	
240ab504d4ba6808c9e284b5963f3e9d	1,2,3,4,6,7,12,15,28,42,66,67,43,120	VoIP Device/Yealink VoIP	88	
c96325987eb2f097e692967507893402	1,3,6,42,43,2,66	VoIP Device/Aastra VoIP	87	
4c1b2e0e0dacf5e0fcc3279bd00f5e90	15,3,6,44,46,47,31,33,249,43,252,12	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.1,5.2	87	
bcd53c324e6ef0b56f5a33ede6aa2e15	1,3,67,43,60	Network Boot Agent/Apple Netboot	87	
474846f826c15e1695321d0112186825	1,28,66,3,4,42,2,6,15	VoIP Device/Polycom VoIP/Polycom SoundPoint IP/Polycom SoundPoint IP 430	87	
3cf3c8556a99ede5bfe455e383ceeaa5	1,3,6,15,28	Hotway LanDrive	50	
9e60ff3c17459791c30853469ed2a3e2	51,1,3,58,59,12,44,54,6,15,144	Printer or Scanner/Xerox Printer	87	
5246276c06be9f4731c4afd413b43d9e	6,3,1,15,66,67,13,12	Printer or Scanner/HP Printer	87	
52de03af47671e7f69bd3b81bbbb4655	1,66,6,3,67,12,150	Switch and Wireless Controller/Cisco Switches/Cisco Catalyst 29xx	87	
b422effb8fe4450ebd9ea00fb6b0e2f5	1,15,3,6,44,46,47,43,77,252	Operating System/Windows OS/Microsoft Windows Kernel 4.x/Microsoft Windows Kernel 4.10	87	
2600c1dffe2246b6c99c53fd85ab74a1	1,28,54,58,59,60,43,3	VoIP Device/Alcatel IP Phone/Alcatel Advanced Reflex IP Phone	87	
92db395887b52bf6a12e48962ebe5767	1,3,6,15,67,43,60	Operating System/Apple OS	87	
5bd3c198753efaf887b913988d96129c	1,28,2,3,15,6,12,40,41	Operating System/Linux OS/SUSE Linux/Novell Desktop	87	
f10d1ad0c054452d0b6c190405c5b7ad	1,28,3,43,128,131,144,157,188,191,205,219,223,224,227,230,232,235,238,241,244,247,249,251,254,58,59,66	VoIP Device/Nortel VoIP/Nortel IP Phone	87	
e54c326dffda1ce600a4fdb7b860821f	3,1,6,12,15,67,66,43	VoIP Device/Sunrocket VoIP Gizmo	87	
db2179ac0fd92f683be3929bc588ea63	1,15,3,6,44,46,47,31,33,121,249,43,0,128,64	Operating System/Windows OS/Microsoft Windows Kernel 6.x/Microsoft Windows Kernel 6.0	87	
9fe07f8dac53006ae466d8b166af00df	79,78	Network Boot Agent/Novell Netware Client	87	
8193b413c72fe24c54164273b9284eb4	6,3,1,15,66,67,13,44,12,81,252	Printer or Scanner/HP Printer	87	
8e9678987e153c33946b9a4799f6b960	1,121,33,3,6,12,15,28,42,51,54,58,59,119	Operating System/Linux OS/Generic Linux	87	
39c10a5965989e867a6c844c0cf2c933	1,3,6,15,44,46,47,137,215,224,226	Thin Client/Neoware Capio Windows CE	87	
128c5415f12642e1ebd9069e0240f5ac	1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,252,42	Operating System/Linux OS/RedHat/Fedora-based Linux/Fedora/Fedora 15 or 16 based distro	87	
d79d7e585f563526303eb23e3fcdd8c6	1,3,28,6,15	Gaming Console/Sony Gaming Console/Playstation/Playstation 3 or Playstation Portable (PSP)	87	
756dedfa6418b44fd4d75eab28633903	1,249,3,6,12,15,28,33,40,41,42,44	Router, Access Point or Femtocell/Router/Trendnet Wireless Router	87	
c5eee0dd497045c110852cb7b6fa753e	1,3,6,12,42,44,51,54,58,59,128,66,120,129,130,131,132,133,134,135,224,138,125,43,225,226	VoIP Device/Mitel IP Phone	88	
c9d0f3c75aab4a5fd651396f19695536	1,3,6,15,112,113,78,79	Operating System/Apple OS/Mac OS X or macOS/Mac OS X	87	
1154651b76bbca7528e891d016f285d0	85,86,87	Network Boot Agent/Novell Netware Client	87	
181be29e0dc8e72cc88c0e2c16dcaa25	1,15,3,6	Phone, Tablet or Wearable/Apple Mobile Device/Apple iPod	87	
120c4b86573fa69b00d4964c476fd9ea	1,3,4,43	Switch and Wireless Controller/HP ProCurve Switches	87	
6de0791c5bea2e7e731d870a38ee7484	1,28,2,3,15,6,12,40,41,42,26	Operating System/Linux OS/RedHat/Fedora-based Linux	87	
900a8b4bff9d01f70b8251ca79df7a7e	1,3,5,6,49,13,15,17,23,28,42,50,51,53,54,56,66,67	Samsung S8500	50	
ce3023d99364ab9eab8a859e3c11de1c	1,28,2,3,15,6,12,46,44	Operating System/Linux OS/Linspire	87	
70c995f77f0cc2c4d4d9e668d5eb61c3	1,3,6,15,28,44,47	Printer or Scanner/Ricoh Printer/Ricoh Multifunction Printer	87	
5fafd12fdcc66083453eb4b9662ef260	1,3,44,6,7,12,15,22,54,58,59,69,18,43,119,81,153,154	Printer or Scanner/HP Printer	87	
8848fb2507c53c29cb3ea21945c78851	1,3,6,12,15,23,28,29,31,33,40,41,42,9,7,200,44	Operating System/Linux OS/Generic Linux	87	
82754f446d62c6084f2884fb8a08013f	1,3,6,15,23,51,54	Audio, Imaging or Video Equipment/Motorola NIM100	87	
8c3ba7572dfa8b528fb6da9bf697b1c0	1,3,6,12,15,28,42,40	Printer or Scanner/Epson Printer	87	
95ba59cd30a82c55cf80a08ce8913723	1,28,2,3,15,6	Barnes and Noble Nook (eReader)	50	
ff2c3ed9d86555e5da986d6b2e1b9cea	1,15,3,6,44,46,47,66,1,3,6,15,44,46,47	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87	
5283df9f4f74046fbdecbb336d949f2d	1,2,3,6,12,15,26,28,85,86,87,88,44,45,46,47,70,69,78,79	Printer or Scanner/Xerox Printer	87	
84e7a01b19614377e492037697763b97	1,28,2,3,15,6,12,44,47	Operating System/Linux OS/Debian-based Linux	87	
6f52e2e10dda39249c323b624c10cac7	15,3,6,44,46,47,31,33,249,43,252	Operating System/Windows OS/Microsoft Windows kernel 5.x/Microsoft Windows Kernel 5.1,5.2	87	
81c6dbe08aa8108bc53861f3173760c3	1,33,3,6,12,15,28,42,51,58,59,119	Operating System/Google OS/Android OS	87	
4b9223500d4718ca1db44c1ed038fb6c	28,2,3,15,6,12,40,41,42	Operating System/Linux OS/RedHat/Fedora-based Linux	87	
8d51fdfb93ad30bdf7f2ed5fd0776041	1,3,6,15,66,69,43,176	VoIP Device/Avaya IP Phone	87	
9f96da28067889e6af2fc153aaa2cb77	1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,42	Operating System/Linux OS/RedHat/Fedora-based Linux/RHEL 6.4 or Centos6.4	87	
3469b3a9a87612c02c145b9c149dae9d	1,3,44,6,7,12,15,22,54,58,59,69,18,144,119	Printer or Scanner/HP Printer	87	
44732e1c8c0d27e4edde8ef6a956d42d	1,3,6,15,12,69,70,88,42	Monitoring and Testing Device/APC/NetBotz WallBotz 400C	87	
94e012fde4dc733f96d9620627791941	1,3,6,12,15,28,33,51,58,59,119,121	Operating System/Google OS/Android OS	87	
a09f97325d185b4313f0e598624e513c	1,3,6,12,15,17,23,28,29,31,33,40,41,42,119	Operating System/Linux OS/Gentoo Linux	87	
5831bce2248e5970c993adb9260eec96	1,3,66,67,54,129,150,131,132,6,15,100	Switch and Wireless Controller/Cisco Switches/Cisco Small Business	87	
ad1aa9adc33a26c68ada0785b2e639d1	1,15,3,6,43	Router, Access Point or Femtocell/Wireless Access Point/Enterasys WAP/Enterasys or Trapeze Wireless Access Point	87
7fa15642c7d22c817a6a614068a85afa	3,51,1,15,6,66,67,120,44,43,150,12,7,42	Switch and Wireless Controller/Juniper Switches	73
9b1ee9aff3eb29371efe446ac89e5c3f	1,3,6,15,26,28,51,58,59,43	Operating System/Google OS/Android OS	87
ccfe2db9ed5c1e1233e85f2b577d05df	1,2,3,6,15,26,28,88,44,45,46,47,70,69,78,79,120	Printer or Scanner/Xerox Printer	73
39950102d6897635453348eea2b0e340	1,121,3,6,15,119,252,95,44,46	Operating System/Apple OS	87
9790d9d687e15939dfb08cd4e275d107	1,121,33,3,2,6,7,15,42,43,51,58,59,66,67,120,125	VoIP Device	29
365a6fa3f855d47e2c4cf58bb7e3bec8	1,3,51,54	Thin Client/Broadcom NetXtreme II	87
97729a05dd6b5dad2a896ce48b4381c8	1,3,15,44,46	Printer or Scanner/Konica Minolta Printer/Konica Minolta Multifunction Printer	87
de424ecf8b8d7e9b87dd7058651bcce7	1,3,66,67,54,125,129,150,6,15,100	Switch and Wireless Controller/Cisco Switches/Cisco Small Business	87
f9aa73929514758fe1f99cf3c98bc19e	1,3,44,6,7,12,15,22,54,58,59,69,18,43,119,81,153,154,144	Printer or Scanner/HP Printer	87
af5e64e042eb1a31856089e8517624f0	1,3,12,15,6,26,33,121,42	Operating System/Windows OS	87
be4f06c316d081f3d27418dfe0081eba	1,28,2,3,15,6,119,12,44,47,26,121,42,249,33,252	Operating System/Linux OS/Generic Linux	87
9e86bc86c8a2d062fd8125b851538757	3,1,252,42,6,12	Operating System/Tizen OS	87
071352faefd6a6d926e1c6b920dc38ba	6,3,1,15,66,67,13,44,2,42,120,125,12	Printer or Scanner/Brother Printer	73
d0be9e3b99384d66c5013153e855648a	1,121,249,3,6,12,15,28,33	Router, Access Point or Femtocell	66
55fd3087605747b2b7dcefe409493787	120,43	Operating System/Windows OS	73
33bc63c3bf7f9bec24b44fcf5a148ba0	1,6,3,58,59	Robotics and Industrial Automation/Sensaphone Remote Monitoring	87
74b29a58b81d24f42492706342783259	6,3,1,15,66,67,13,44,2,42,12	Printer or Scanner/Brother Printer	87
f77b72a9cbe1691c1c96602c471b09c0	3,1,15,44,12,6	Printer or Scanner/HP Printer	87
cbcad79acba6bfc63f24380f7c3e9454	1,3,6,15,26,28,51,58,59	Operating System/Google OS/Android OS	87
02c94b9f18112180acf6c8ea84250b39	1,3,6,12,15,28,33,42,249	Router, Access Point or Femtocell	66
c1657e3115bdc4698b1047183ceb2f75	6,3,1,15,12,44,81,69,43,18,66,67,150,7	Printer or Scanner/HP Printer	87
1ba0097522abea6a46f3eb015e220a02	1,3,15,6,212	Router, Access Point or Femtocell/Router/Cisco/Linksys Router	87
ba8acc3498ccc44294fe9fc47f3f7022	1,28,3,6,15,35,66,150	VoIP Device/Cisco VoIP	87
6141ffd1aa08ad4d12c97a5f775fb554	1,3,6,12,15,28,33,42,121,249	Router, Access Point or Femtocell	66
2ebfb8ca4a9fc6994320f8bb396efdd8	1,3,6,12,15,28,42,121,212	Router, Access Point or Femtocell	66
2eb6f4b3ffd2ca7508824dd6a1814f2c	1,3,6,12,15,28,42,121	Router, Access Point or Femtocell	66
1b8243a59d4dd3bb362d374745e34390	1,121,33,3,6,12,15,28,44,51,54,58,59,81,119,252	Printer or Scanner/HP Printer	87
9b8eca14b0939794872ba7846a709a16	1,3,6,12,15,28,40,41,42,43,119,121	Audio, Imaging or Video Equipment/Video Equipment (Smart TV, Smart Players, etc.)/Infomir IP TV	87
41efaea5187e814c86b537f7293d589d	1,121,3,6,15,119,252	Operating System/Apple OS	87
18e755fd06072cedffaa1518890873f3	1,33,3,6,15,28,51,58,59,43	Operating System/Google OS/Android OS	87
0c294e049a5c824306cf6918dc4b19e0	58,59,6,15,66,67,51,54,1,3,125	VoIP Device/Panasonic VoIP/Panasonic KX-UDS124CE SIP-DECT Base Station	87
a2133b5e525d9b176febad7a59bf6e75	1,121,33,3,6,12,15,28,44,51,53,54,58,59,81,119,252	Printer or Scanner/HP Printer	87
40a0f7239490091ab78ac7c727749118	1,3,6,12,15,28,33,40,41,42,44,46,47,121,212,249	Router, Access Point or Femtocell	66
4ea208e947ec3d01c12fd536aefdedf9	1,28,3,121,26,12,15,119,6,40,41,87,85,86,44,45,46,47,42,249,33,252	Operating System/Linux OS	87
1221bdb25497e7ed9f0ef115655f3f38	6,3,1,15,66,67,13,44,119,12,81,252	Printer or Scanner/HP Printer	87
266830d56b6550a542e3723602adb63c	1,3,6	Gaming Console/Microsoft Gaming Console/Xbox 360	29
74b20235ac310e406a9fdd0eb0e1cb6c	1,3,6,15,35,66,150,2,7,42,43,58,59,159,160	VoIP Device/Cisco VoIP	87
80a0713af2f9435bc6e2a830a105236b	1,3,6,12,15,28,33,44,121,249,212	Router, Access Point or Femtocell	66
d304ec3f1ca1483e715d0ee41800bfa1	1,121,249,3,6,12,15,28,212,33	Router, Access Point or Femtocell/Router/Netgear Router	87
8d9a9739f0f10428b7b3292e9b381016	1,3,6,15,31,33,43,44,46,47,121,249,252	Operating System/Windows OS	87
86eed4bae372606b6c52393465543d87	1,3,6,15,31,33,43,44,46,47,119,121,249,252	Operating System/Windows OS/Microsoft Windows Kernel 10.0	87
9f6663cc09fd67f78f36bd80bac11ae2	1,3,42,4,6,12,15,26,44,51,54,58,59,190	Printer or Scanner/Lexmark Printer	87
388986ec86c33bec049ed0b01790aa92	6,3,1,15,12,44,81,69,42,43,18,66,67,150,7	Printer or Scanner/HP Printer	87
d42dff3a5b524eba5653c8aa8d503d95	1,28,2,3,15,6,12,44,47,121,249,33,252,42	Audio, Imaging or Video Equipment/IP Camera/WiLife IP Camera	87
67ab053a10dc5992c3882a3e04e03f9f	1,121,3,33,6,42,138,43	Router, Access Point or Femtocell/Router/MikroTik (RouterOS) Router	87
4e80ecedcf8cd1faf0ffab1507cef142	1,3,12,15,6,2,26,28,33,40,41,42,54,119,121,249,252	Operating System/Linux OS	87
5e2da3332661c27201dba8fc5ff61194	1,3,6,12,15,28,42,43	Router, Access Point or Femtocell/Wireless Access Point/Adtran WAP	87
a73d4e4b095e3c29016b6439ab83c0a0	1,3,6,12	Internet of Things (IoT)/Chamberlain MyQ Smart Home	87
e1092351fbc6204de3afe0c89094868c	1,3,6,10,12,14,15,28,42,87	Audio, Imaging or Video Equipment/King Champion WiFi Speaker	87
32f7c9dcd4c5e95a17add54ce04feb12	1,3,6,22,23,24,33,42	Router, Access Point or Femtocell/Wireless Access Point/AboCom WAP	87
cf856d36c1c255aec0eb98373856ee7b	1,3,28,6,15,44,46,47,31,33,121,43	Internet of Things (IoT)/Generic IoT/Espressif	87"""
    
    # Parser la base de données
    db = parse_dhcp_fingerprints(sample_file_content)
    #recuperer le input_fp entrer dans les argument commande
    if len(sys.argv) != 2:
        print("Usage: python fingerprint.py <fingerprint>")
        sys.exit(1)
    input_fp = sys.argv[1] 
    matches = find_best_match(input_fp, db)
    if not matches:
        print("No fingerprint")
    else:
        print(matches[0]['device_name'])
    # Afficher les top résultats
    # for i, match in enumerate(matches[:5], 1):
    #     print(f"{i}. {match['device_name']}")
    #     print(f"   Matching fingerprint: {match['fingerprint']}")
    #     print(f"   Original score: {match['original_score']}")
    #     print(f"   Similarity score: {match['similarity_score']:.2f}")
    #     print("-"*50)
