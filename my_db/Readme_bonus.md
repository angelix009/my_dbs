# my_db

## Bonus : Backtrace

### Description
J'ai implémenté le bonus backtrace qui permet d'afficher la pile d'appels du programme en cours de débogage, similaire à la commande bt de GDB.

### Commandes disponibles
- `bt` ou `backtrace` : Affiche la pile d'appels courante

### Démonstration de l'utilisation

Voici un exemple complet d'utilisation montrant le bon fonctionnement du backtrace :

```bash
hamid@hamid-ThinkPad-E14-Gen-5:~/epita-apprentissage-mydbs-apping-2027-crystal/my_db$ ./my_db test
> c
before breakpoint
> b func1
Point d'arrêt ajouté à 0x401775
> b func2
Point d'arrêt ajouté à 0x40178f
> c
Breakpoint at 0x401775
> c
test1
Breakpoint at 0x40178f
> r
rax: 0x6
rbx: 0x7fff28c7da28
rcx: 0x1
rdx: 0x1
rsi: 0x21977a0
rdi: 0x4c81b0
rbp: 0x7fff28c7d830
rsp: 0x7fff28c7d828
r8:  0x4c81b0
r9:  0x21977a0
r10: 0x6e
r11: 0x246
r12: 0x1
r13: 0x7fff28c7da18
r14: 0x4c17d0
r15: 0x1
rip: 0x401793
eflags: 0x202
> bt
Back Trace:
#0  0x401793 dans func2
#1  0x401c1a dans __libc_start_call_main
> c
test2
after breakpoint
Programme terminé avec le code 0
```

### Comment ça marche
L'implémentation utilise :
1. Les registres RBP et RIP pour naviguer dans la pile d'appels
2. La table des symboles du fichier ELF pour retrouver les noms des fonctions
3. L'API ptrace pour lire la mémoire du programme débogué

### Limitations
- La profondeur de la pile d'appels dépend de la compilation
- Les fonctions optimisées peuvent ne pas apparaître correctement dans la pile
- Les noms de fonctions dépendent des symboles de débogage disponibles
