# FCFS 2026 - Forensics - Web Logs

- **Catégorie :** Forensics

- **Description :** Vous avez à disposition les logs d'un serveur web exposé sur Internet. Du fait de son exposition publique, des tentatives d'attaques variées existent dans les logs.

    Trouvez le CWE ID de l'attaque qui a réussi au sein des logs de ce serveur web (ex: CWE-79). Donnez la date où l'attaque a réussi (format : MM/DD) Donnez les routes requêtées pour lesquelles l'attaque a fonctionné. Les requêtes doivent être dans l'ordre temporel, séparées par des tirets '-' '(ex: /var/log/access.log-/index?params=value).

    Note : dans cette attaque, l'attaquant a réussi à extraire des fichiers sensibles.
    Format du Flag : `FCSC{CWE-XXXXX-MM/DD-requests}`, [`webserver.log.gz`](webserver.log.gz)

- **Résumé de l'analyse :** Identification d'une attaque de type Path Traversal (CWE-22) le 07 mai, permettant la lecture de clés SSH privées et de fichiers de configuration système.

## Analyse

### 1. Recherche d'anomalies dans les logs
Sur un serveur web, les attaques par saut de répertoire (Path Traversal) sont caractérisées par la présence de séquences ../ ou de leur encodage URL (%2e%2e%2f). Nous filtrons les logs pour trouver les requêtes ayant retourné un code HTTP 200 (succès) tout en contenant ces motifs :

```Bash
grep " 200 " webserver.log | grep -E "\.\./|\.\.%2f|%2e%2e"
```

### 2. Identification de l'attaque réussie
Le filtrage remonte deux lignes critiques survenues le 7 Mai :

```Plaintext
May  7 00:40:21 ... "GET /?asset=../../../../home/webserver/.ssh/id_rsa HTTP/1.0" 200 2500
May  7 00:40:22 ... "GET /?asset=../../../../home/webserver/.ssh/known_hosts HTTP/1.0" 200 2750
```

- CWE ID : L'utilisation de `../` pour sortir de la racine web et accéder à des fichiers arbitraires sur le système de fichiers correspond à la faiblesse CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal').

- Date : Le timestamp indique le `07/May`. Format MM/DD : `05/07`.

- Impact : L'attaquant a réussi à extraire la clé privée SSH (`id_rsa`) de l'utilisateur `webserver`, ce qui lui permet potentiellement de prendre le contrôle total du serveur.

### 3. Chronologie des requêtes
L'attaque a fonctionné sur deux routes spécifiques, dans cet ordre temporel :

1. `/?asset=../../../../home/webserver/.ssh/id_rsa`

2. `/?asset=../../../../home/webserver/.ssh/known_hosts`

## Conclusion
Le serveur était vulnérable au Path Traversal via le paramètre `asset`. L'attaquant a d'abord récupéré la clé privée pour l'accès, puis le fichier `known_hosts` pour identifier d'autres cibles potentielles sur lesquelles rebondir.

## Flag

```Plaintext
FCSC{CWE-22-05/07-/?asset=../../../../home/webserver/.ssh/id_rsa-/?asset=../../../../home/webserver/.ssh/known_hosts}
```