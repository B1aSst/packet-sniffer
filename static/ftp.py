from scapy.all import *

trames = rdpcap("network-samples/ftp.pcapng")
username = []
password = []
file = []
n = 0
for trame in trames:
    try:
        if (trame[0][1].dport) == 21 or (trame[0][1].sport) == 21:
            try:
                data = trame[Raw].load  # on récupère les donnés dans ftp
                data = data.decode("utf-8")  # on le decode pour l'avoir proprement
                data_list = list(
                    data.split()
                )  # on crée une liste avec les donnés split
                if "USER" in data_list:
                    username.append(data_list[-1])
                elif "PASS" in data_list:
                    password.append(data_list[-1])
                elif "230" in data_list:
                    print(f"^*^ Un utilisateur vient de se connecter!")
                    print(f"^*^ {trame[0][1].src} vers {trame[0][1].dst}")
                    print(f"^*^ Le nom d'utilisateur est : {username[-1]}")
                    print(f"^*^ Le mot de passe est : {password[-1]}")
                elif "226" in data_list:
                    doc = open("doc.odt", "wb")
                    doc.writelines(file)
                    doc.close()
                elif "QUIT" in data_list:
                    print(f"^*^ La connexion est terminé")
            except:
                continue
        elif (trame[0][1].sport) == 20 or (trame[0][1].dport) == 20:
            n += 1
            data = trame[Raw].load
            if n >= 1:
                # print(data)
                file.append(data)
    except:
        continue
