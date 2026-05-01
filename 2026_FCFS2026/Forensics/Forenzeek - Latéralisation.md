# FCFS 2026 - Forensics - Forenzeek Latéralisation

- **Catégorie :** Forensics

- **Description :** Suite à la compromission initiale que vous avez analysée, l'attaquant ne se serait pas arrêté là ! Il semblerait que l'administrateur du réseau ait détecté une activité inhabituelle sur sa machine d'administration du parc. Pouvez-vous identifier l'uid de la connexion ayant permis à l'attaquant de compromettre la machine de l'administrateur ? Format du flag : `FCSC{uid}`, [`forenzeek.csv.gz`](forenzeek.csv.gz)

- **Résumé de l'analyse :** Détection d'un mouvement latéral via le protocole WinRM (port 5986) à destination de l'IP `192.168.1.38`.

## Analyse

### 1. Stratégie : Recherche du mouvement latéral
Après la compromission initiale, un attaquant cherche généralement à s'étendre sur le réseau (mouvement latéral). L'objectif est de trouver une connexion sortante de la machine infectée (`192.168.1.42`) vers une nouvelle cible interne, en particulier vers des services d'administration à distance.

### 2. Identification des cibles potentielles
Nous avons listé toutes les destinations uniques contactées par la machine infectée pour identifier des flux atypiques :

```python
import pandas as pd

# Chargement des logs Zeek
df = pd.read_csv('Forenzeek.csv', sep='\t', comment='#', names=['ts','uid','orig_h','orig_p','resp_h','resp_p','bytes'])

# Lister toutes les destinations uniques de la machine infectée
targets = df[df['orig_h'] == '192.168.1.42'][['resp_h', 'resp_p']].drop_duplicates()
print(targets)
```

On observe de nombreuses connexions vers les ports 80, 443 et 7680, mais une ligne se détache :

- IP : `192.168.1.38`

- Port : `5986` (WinRM HTTPS)

### 3. Isolation de l'UID
Une fois la cible et le service identifiés, nous extrayons les détails de cette session spécifique :

```Python
# Filtrage sur la cible et le port WinRM
result = df[(df['resp_h'] == '192.168.1.38') & (df['resp_p'] == 5986)]
print(result)
```

### 4. Résultat
L'analyse confirme une session WinRM active avec un transfert de données significatif :

| ts | uid | orig_h | resp_h
| - | - | - | -
| 1.756309e+09 | Connexion via navigateur (212.114.18.5) | 192.168.1.42 | 192.168.1.38

## Interprétation
L'attaquant a utilisé des identifiants (probablement récupérés sur la première machine) pour se connecter à distance via WinRM à la machine de l'administrateur. Le volume de 34 224 bytes indique l'exécution de commandes ou le transfert de scripts lors de cette phase de latéralisation.

## Flag

```text
FCSC{9a4fe41babf12d1bdf}
```