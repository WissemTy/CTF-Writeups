# Midnight Flag 2026 - Forensics - Duke's DBar

- **Catégorie :** Forensics

- **Description :**  In every case, investigators find the same afterimage: the victim's accounts are briefly used to access their own infrastructure, as if the killer wanted someone to watch what he did next. Then everything goes quiet again. Last night, a Grafana monitoring instance tied to a victim's environment was exposed to the Internet for a short window. During that time, a local file was exfiltrated using a recent vulnerability. You recovered only two artifacts from the incident window:

    **Provided artifacts**

    - `grafana.log`
    - `grafana.db`

    The attacker blended into background monitoring activity and Internet noise.
Your task is to isolate the malicious actions and reconstruct the truth. `MCTF{CVE-XXXX-XXXXX:path:ip:username}` [`DukesDBar.zip`](DukesDBar.zip)

- **Résumé de l'analyse :** Exploitation de [CVE-2024-9264](https://nvd.nist.gov/vuln/detail/CVE-2024-9264) via DuckDB (read_blob), permettant la lecture de fichiers locaux et l'exfiltration de `/var/lib/grafana/ctf/secret.csv` depuis l'IP `85.215.144.254` avec le compte `editor2`.


## Analyse 

### 1. Exploration des logs

Le fichier `grafana.log` étant volumineux, une première étape a consisté à identifier les types de logs présents :

```bash
grep -o 'logger=[^ ]*' grafana.log | sort | uniq -c | sort -rn
```

Cela permet de faire ressortir plusieurs catégories utiles :

- `context` → requêtes HTTP

- `auth` → authentification

- `login_attempt` → tentatives de connexion

### 2. Identification des adresses IP

```bash
grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' grafana.log | sort | uniq -c | sort -rn
```

Résultat :

- `172.22.0.1` → réseau interne (Docker)

- `212.114.18.5` → activité importante (navigateur)

- `85.215.144.254` → activité externe suspecte (faible volume mais automatisée)

### 3. Analyse de la base de données

La base SQLite `grafana.db` contient les informations utilisateurs et sessions. Liste des utilisateurs :

```sql
SELECT id, login, email, is_admin FROM user;
```

Utilisateurs identifiés : admin, viewer1, editor1, editor2, sa-1-checkup

### 4. Corrélation sessions / IP

Analyse des tokens d'authentification :

```sql
SELECT * FROM user_auth_token;
```

Observation :

L'IP `85.215.144.254` utilise un User-Agent `python-requests`. Elle est associée au userID = 5, ce qui correspond à lutilisateur `editor2`. Cela indique très probablement un script automatisé.

### 5. Analyse des actions suspectes

Filtrage des logs sur cette IP :

```bash
grep "85.215.144.254" grafana.log
```

Puis focus sur la fenêtre critique :
```bash
grep "10:20:16\|10:20:37" grafana.log
```

Test de l'attaquant *(validation de la vulnérabilité, utilisé pour vérifier la capacité à lire des fichiers locaux)* :

```sql
SELECT content FROM read_blob('/etc/passwd')
```

Exfiltration réelle *(avec le fichier cible contenant les données sensibles)*:
```sql
SELECT content FROM read_blob('/var/lib/grafana/ctf/secret.csv')
```

### 6. Identification de la vulnérabilité

Version de Grafana : `head -30 grafana.log | grep -i version` -> Grafana version 11.0.0. Cette version est associée à une vulnérabilité permettant d'utiliser read_blob() via le moteur DuckDB. CVE lié : [CVE-2024-9264](https://nvd.nist.gov/vuln/detail/CVE-2024-9264) 

## Interprétation

L'attaque repose sur l'utilisation du moteur DuckDB intégré à Grafana pour effectuer une requête SQL malveillante exploitant `read_blob()`, puis lire les fichiers locaux sans restriction

L'attaquant :

1. Se connecte avec le compte `editor2`

2. Utilise un script (`python-requests`)

3. Teste l'accès avec `/etc/passwd`

4. Exfiltre ensuite le vrai fichier cible

### Chronologie

| Heure    | Action                                  |
| -------- | --------------------------------------- |
| 10:08    | Connexion via navigateur (212.114.18.5) |
| 10:18    | Activité sur plusieurs comptes          |
| 10:20:16 | Test `read_blob('/etc/passwd')`         |
| 10:20:37 | Exfiltration du fichier cible           |
| 14:08    | Retour de surveillance                  |


## Flag


```text
MCTF{CVE-2024-9264:/var/lib/grafana/ctf/secret.csv:85.215.144.254:editor2}
```