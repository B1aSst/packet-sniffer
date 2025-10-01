from scapy.all import *

trames = rdpcap("network-samples/ftp-total.pcapng")


def check_login(nomutil, mdp):
    """recupérer le mon d'utilisateur et le password"""
    print(nomutil)
    print(mdp)


def verifie_ftp(pkt):
    """vérifie la présence de ftp dans les trames"""
    for trame in pkt:
        try:
            if trame["TCP"].dport == 21 or trame["TCP"].sport == 21:
                return True
        except:
            continue
    return False


def login(trames):
    id_util = []
    mdp = []
    if verifie_ftp(trames):
        pass
    else:
        return
    for i in range(len(trames)):
        try:
            a = trames[i][Raw].load
            if (a[0:4]) == b"USER":
                a = a.decode("UTF-8").split()
                nom_utilisateur = a[1]
            if (a[0:4]) == b"PASS":
                a = a.decode("UTF-8").split()
                mdp = a[1]
            if (a[0:3]) == b"230":
                check_login(nom_utilisateur, mdp)
            if (a[0:4]) == b"RETR":
                data = a.decode("UTF-8").split()
                print(data[1])
                # print(f')
        except:
            continue
    return data[1]


def recup_fichier():
    liste_fichier = []
    # print(clair)
    # trames[1][Raw].load
    for i in range(len(trames)):
        try:
            if trames[i]["TCP"].sport == 20:
                data = trames[i].load
                # print(data)
                liste_fichier.append(data)

        # clair = trame[Raw].load.split(sep=None)[1].decode('utf-8')
        # print(clair)
        except:
            continue
    liste_fichier = liste_fichier[1:]
    fichier = open("ftp.odt", "wb")
    fichier.writelines(liste_fichier)
    fichier.close()


login(trames)
recup_fichier()
