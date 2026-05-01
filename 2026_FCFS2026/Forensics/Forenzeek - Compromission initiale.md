# FCFS 2026 - Forensics - Forenzeek Compromission initiale

- **Catégorie :** Forensics

- **Description :** Une compromission a été observée sur la machine dont l'adresse IP est` 192.168.1.42`. Cette compromission a été réalisée via un email malveillant contenant une charge utile assez volumineuse. Pouvez-vous retrouver l'uid de la connexion associée au téléchargement du mail ? Format du flag `FCSC{uid}`, [`forenzeek.csv.gz`](forenzeek.csv.gz)

- **Résumé de l'analyse :** Analyse de logs réseau Zeek (format TSV/JSON) et filtrage par volume de données transférées sur les ports de messagerie sécurisée (IMAPS/993).

## Analyse

### 1. Compréhension des logs Zeek

Les logs fournis contiennent les champs essentiels : ts (timestamp), uid (identifiant unique de connexion), orig_h (source), resp_h (destination), resp_p (port de réponse) et bytes (volume de données).

L'adresse de la victime est 192.168.1.42. On remarque des connexions vers l'IP 192.168.1.4 sur le port 993, qui correspond au protocole IMAPS (Internet Message Access Protocol over TLS/SSL), utilisé pour la relève de courrier électronique.

### 2. Stratégie de recherche
L'énoncé précise que l'email contient une charge utile volumineuse. La méthode la plus rapide consiste à trier les connexions impliquant la victime par ordre décroissant de taille (bytes).

### 3. Extraction via script Python
Pour traiter le volume de logs, un script simple permet d'isoler les sessions les plus lourdes :

```Python
import pandas as pd

# Chargement des logs (exemple si stockés en CSV/TSV)
df = pd.read_csv('forenzeek.csv')

# Filtrage : victime IP et port IMAPS (993)
victim_logs = df[df['orig_h'] == '192.168.1.42']

# Tri par volume de bytes (décroissant)
sorted_logs = victim_logs.sort_values(by='bytes', ascending=False)

print(sorted_logs[['uid', 'resp_p', 'bytes']].head(1))
```

### 4. Résultat
La connexion avec l'UID `c2ad3fb71679d16ec9` présente un transfert de 102 025 bytes, ce qui est nettement supérieur aux autres échanges de mails observés dans les logs.

## Flag

```Plaintext
FCSC{c2ad3fb71679d16ec9}
```