# FCFS 2026 - Misc - Times Square

- **Catégorie :** Misc

- **Description :** On vous donne accès à un terminal d'accès distant, trouvez vite son flag avant que le système ne se bloque. Connexion : ssh -p 2051 challenges.fcsc.fr

- **Résumé de l'analyse :** Exploitation d'un Integer Overflow sur les dimensions du terminal (TTY) envoyées via SSH pour valider une équation temporelle.

## Analyse

### 1. La Négociation du Terminal (TTY)

Lors d'une connexion SSH, le client transmet au serveur les dimensions de son terminal (colonnes `X` et lignes `Y`). Le challenge vérifie ces valeurs et impose une contrainte mathématique pour délivrer le flag.

### 2. L'Énigme Mathématique

Le serveur impose que la somme des dimensions et du temps écoulé soit égale à une constante : `X + Y + t = 42` (Avec `t` qui représente le temps écoulé en secondes depuis la connexion)

### 3. Exploitation de l'Integer Overflow\

Le serveur utilise des entiers non-signés de 16 bits (`uint16_t`) pour stocker `X` et `Y`. Ces variables ont une valeur maximale de `65535`. Si la somme dépasse cette limite, elle subit un wrap-around (elle repart de zéro).

Pour obtenir un résultat de `42` avec des dimensions positives, il faut provoquer ce dépassement :

1. On choisit des valeurs dont la somme réelle est légèrement supérieure à `2^{16} (=65536)`.

2. Par exemple : `X = 50000` et `Y = 15570`.

3. Somme réelle : `65570`.

4. Valeur perçue par le serveur (Modulo 65536) : `65570 - 65536 = 34`.

### 4. Résolution

Il suffit de mentir au serveur sur la taille de notre terminal avec la commande stty, puis d'attendre que le temps `t` complète l'équation.

```bash
# On définit des dimensions gigantesques pour provoquer l'overflow
stty rows 15570 cols 50000 

# On se connecte au challenge
ssh -o StrictHostKeyChecking=no -p 2051 challenges.fcsc.fr
```

Une fois connecté, la somme `X+Y` vaut `34` aux yeux du serveur. Après 8 secondes d'attente, `t` atteint `8`, l'équation `34 + 8 = 42` est vérifiée et le flag s'affiche.

## Interprétation
Ce challenge illustre comment une mauvaise gestion des types d'entiers (overflow) peut être utilisée pour contourner des vérifications logiques, même sur des paramètres d'environnements comme la taille d'un terminal.

## Flag

```text
FCSC{2b1150bfd7ad93f72a184764bcae0f51521fcaf796b0997288}
```