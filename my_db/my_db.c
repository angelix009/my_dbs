#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <fcntl.h>

#define TAILLE_MAX_CMD 256
#define MAX_POINTS_ARRET 100

struct donnees_elf {
   unsigned char *debut;
   Elf64_Ehdr *entete;
   Elf64_Shdr *table_sections;
   char *table_chaines;
   size_t taille;
   char *table_symboles;
   size_t nb_symboles;
   Elf64_Sym *symboles;
};

struct point_arret {
   int numero;
   unsigned long adresse;
   long donnee_originale;
   char *symbole;
   int actif;
};

struct debogueur {
   pid_t pid_fils;
   struct point_arret points_arret[MAX_POINTS_ARRET];
   int nb_points_arret;
   struct donnees_elf elf;
};

static int lire_fichier_elf(const char *chemin, struct donnees_elf *donnees) {
   int fd = open(chemin, O_RDONLY);
   if (fd == -1)
       return 0;

   off_t taille_fichier = lseek(fd, 0, SEEK_END);
   if (taille_fichier == -1 || lseek(fd, 0, SEEK_SET) == -1) {
       close(fd);
       return 0;
   }
   donnees->taille = (size_t)taille_fichier;

   donnees->debut = malloc(donnees->taille);
   if (!donnees->debut) {
       close(fd);
       return 0;
   }

   ssize_t lu = read(fd, donnees->debut, donnees->taille);
   if (lu == -1 || (size_t)lu != donnees->taille) {
       free(donnees->debut);
       close(fd);
       return 0;
   }
   close(fd);

   donnees->entete = (Elf64_Ehdr *)donnees->debut;
   
   if (memcmp(donnees->entete->e_ident, ELFMAG, SELFMAG) != 0) {
       free(donnees->debut);
       return 0;
   }

   donnees->table_sections = (Elf64_Shdr *)(donnees->debut + donnees->entete->e_shoff);
   donnees->table_chaines = (char *)(donnees->debut + 
       donnees->table_sections[donnees->entete->e_shstrndx].sh_offset);

   int trouve = 0;
   for (size_t i = 0; i < donnees->entete->e_shnum; i++) {
       if (donnees->table_sections[i].sh_type == SHT_SYMTAB) {
           trouve = 1;
           donnees->symboles = (Elf64_Sym *)(donnees->debut + 
               donnees->table_sections[i].sh_offset);
           donnees->table_symboles = (char *)(donnees->debut + 
               donnees->table_sections[donnees->table_sections[i].sh_link].sh_offset);
           donnees->nb_symboles = donnees->table_sections[i].sh_size / sizeof(Elf64_Sym);
           break;
       }
   }
   if (!trouve) return 0;
   return 1;
}

static void gerer_signaux(struct debogueur *dbg, int sig) {
   if (sig != SIGTRAP) {
       printf("Programme reçoit le signal %d\n", sig);
       ptrace(PTRACE_CONT, dbg->pid_fils, NULL, sig);
   }
}

static void afficher_registres(pid_t pid) {
   struct user_regs_struct regs;
   if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
       return;

   printf("rax: 0x%llx\n", regs.rax);
   printf("rbx: 0x%llx\n", regs.rbx);
   printf("rcx: 0x%llx\n", regs.rcx);
   printf("rdx: 0x%llx\n", regs.rdx);
   printf("rsi: 0x%llx\n", regs.rsi);
   printf("rdi: 0x%llx\n", regs.rdi);
   printf("rbp: 0x%llx\n", regs.rbp);
   printf("rsp: 0x%llx\n", regs.rsp);
   printf("r8:  0x%llx\n", regs.r8);
   printf("r9:  0x%llx\n", regs.r9);
   printf("r10: 0x%llx\n", regs.r10);
   printf("r11: 0x%llx\n", regs.r11);
   printf("r12: 0x%llx\n", regs.r12);
   printf("r13: 0x%llx\n", regs.r13);
   printf("r14: 0x%llx\n", regs.r14);
   printf("r15: 0x%llx\n", regs.r15);
   printf("rip: 0x%llx\n", regs.rip);
   printf("eflags: 0x%llx\n", regs.eflags);
}

static void afficher_memoire(struct debogueur *dbg, unsigned long addr, int count, char format) {
   for (int i = 0; i < count; i++) {
       errno = 0;
       long data = ptrace(PTRACE_PEEKDATA, dbg->pid_fils, addr + i * 8, NULL);
       if (errno != 0) {
           perror("ptrace peekdata");
           return;
       }
       
       switch (format) {
           case 'x':
               printf("0x%lx: 0x%lx\n", addr + i * 8, data);
               break;
           case 'd':
               printf("0x%lx: %ld\n", addr + i * 8, data);
               break;
           case 'u':
               printf("0x%lx: %lu\n", addr + i * 8, (unsigned long)data);
               break;
       }
   }
}

static void etape_suivante(struct debogueur *dbg) {
   if (ptrace(PTRACE_SINGLESTEP, dbg->pid_fils, NULL, NULL) == -1) {
       perror("ptrace singlestep");
       return;
   }
   int statut;
   waitpid(dbg->pid_fils, &statut, 0);
   if (WIFSTOPPED(statut)) {
       struct user_regs_struct regs;
       ptrace(PTRACE_GETREGS, dbg->pid_fils, NULL, &regs);
       printf("Programme arrêté à 0x%llx\n", regs.rip);
   }
}

static unsigned long recuperer_adresse_symbole(struct debogueur *dbg, const char *symbole) {
   if (!dbg->elf.symboles || !dbg->elf.table_symboles) {
       return (unsigned long)-1;
   }

   for (size_t i = 0; i < dbg->elf.nb_symboles; i++) {
       if (dbg->elf.symboles[i].st_name && 
           ELF64_ST_TYPE(dbg->elf.symboles[i].st_info) == STT_FUNC &&
           strcmp(dbg->elf.table_symboles + dbg->elf.symboles[i].st_name, symbole) == 0) {
           return dbg->elf.symboles[i].st_value;
       }
   }
   return (unsigned long)-1;
}

static void restaurer_point_arret(struct debogueur *dbg, struct point_arret *bp) {
   if (ptrace(PTRACE_POKEDATA, dbg->pid_fils, bp->adresse, bp->donnee_originale) == -1) {
       perror("restauration point arret");
   }
}

static int ajouter_point_arret(struct debogueur *dbg, unsigned long addr) {
   if (addr == 0 || addr == (unsigned long)-1) {
       printf("Adresse invalide pour le point d'arrêt\n");
       return 0;
   }
   
   if (dbg->nb_points_arret >= MAX_POINTS_ARRET) {
       printf("Nombre maximum de points d'arrêt atteint\n");
       return 0;
   }
   
   errno = 0;
   long donnee = ptrace(PTRACE_PEEKDATA, dbg->pid_fils, addr, NULL);
   if (errno != 0) {
       perror("ptrace peek");
       return 0;
   }
   
   long int3 = (donnee & ~0xFF) | 0xCC;
   if (ptrace(PTRACE_POKEDATA, dbg->pid_fils, addr, int3) == -1) {
       perror("ptrace poke");
       return 0;
   }
   
   struct point_arret *bp = &dbg->points_arret[dbg->nb_points_arret++];
   bp->numero = dbg->nb_points_arret;
   bp->adresse = addr;
   bp->donnee_originale = donnee;
   bp->actif = 1;
   
   return 1;
}

static void gerer_point_arret(struct debogueur *dbg) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, dbg->pid_fils, NULL, &regs) == -1) {
        perror("getregs failed");
        return;
    }
    
    unsigned long pc = regs.rip - 1;

    for (int i = 0; i < dbg->nb_points_arret; i++) {
        if (dbg->points_arret[i].adresse == pc && dbg->points_arret[i].actif) {
            if (ptrace(PTRACE_POKEDATA, dbg->pid_fils, pc, 
                      dbg->points_arret[i].donnee_originale) == -1) {
                perror("restauration instruction");
                return;
            }
            
            regs.rip = pc;
            if (ptrace(PTRACE_SETREGS, dbg->pid_fils, NULL, &regs) == -1) {
                perror("setregs failed");
                return;
            }

            printf("Breakpoint at 0x%lx\n", pc);
            if (ptrace(PTRACE_SINGLESTEP, dbg->pid_fils, NULL, NULL) == -1) {
                perror("singlestep failed");
                return;
            }
            
            int status;
            waitpid(dbg->pid_fils, &status, 0);
            if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP) {
                gerer_signaux(dbg, WSTOPSIG(status));
            }
            
            long data = (dbg->points_arret[i].donnee_originale & ~0xFF) | 0xCC;
            if (ptrace(PTRACE_POKEDATA, dbg->pid_fils, pc, data) == -1) {
                perror("remise point arret");
                return;
            }
            
            return;
        }
    }
}
static void continuer_execution(struct debogueur *dbg) {
   if (ptrace(PTRACE_CONT, dbg->pid_fils, NULL, NULL) == -1) {
       perror("ptrace continue");
       return;
   }

   int statut;
   waitpid(dbg->pid_fils, &statut, 0);
   
   if (WIFSTOPPED(statut)) {
       int sig = WSTOPSIG(statut);
       if (sig == SIGTRAP) {
           struct user_regs_struct regs;
           ptrace(PTRACE_GETREGS, dbg->pid_fils, NULL, &regs);
           gerer_point_arret(dbg);
       } else {
           gerer_signaux(dbg, sig);
       }
   } else if (WIFEXITED(statut)) {
       printf("Programme terminé avec le code %d\n", WEXITSTATUS(statut));
   }
}

void traiter_commande(struct debogueur *dbg, char *cmd) {
   cmd[strcspn(cmd, "\n")] = 0;
   char *token = strtok(cmd, " ");
   if (!token) return;

   if (strcmp(token, "quit") == 0) {
       kill(dbg->pid_fils, SIGKILL);
       exit(0);
   }
   else if (strcmp(token, "registers") == 0) {
       afficher_registres(dbg->pid_fils);
   }
   else if (strcmp(token, "continue") == 0) {
       continuer_execution(dbg);
   }
   else if (strcmp(token, "next") == 0) {
       etape_suivante(dbg);
   }
   else if (strcmp(token, "kill") == 0) {
       kill(dbg->pid_fils, SIGKILL);
       printf("Programme tué\n");
   }
   else if (strcmp(token, "x") == 0 || strcmp(token, "d") == 0 || strcmp(token, "u") == 0) {
       char format = token[0];
       token = strtok(NULL, " ");
       if (!token) {
           printf("Usage: %c <count> <addr>\n", format);
           return;
       }
       int count = atoi(token);
       token = strtok(NULL, " ");
       if (!token) {
           printf("Usage: %c <count> <addr>\n", format);
           return;
       }
       
       unsigned long addr;
       char *endptr;
       addr = strtoul(token, &endptr, 0);
       if (*endptr != '\0') {
           addr = recuperer_adresse_symbole(dbg, token);
           if (addr == (unsigned long)-1) {
               printf("Adresse ou symbole invalide\n");
               return;
           }
       }
       afficher_memoire(dbg, addr, count, format);
   }
   else if (strcmp(token, "break") == 0 || strcmp(token, "b") == 0) {
       token = strtok(NULL, " ");
       if (!token) {
           printf("Usage: break <addr|symbol>\n");
           return;
       }
       
       unsigned long addr;
       char *endptr;
       addr = strtoul(token, &endptr, 0);
       if (*endptr != '\0') {
           addr = recuperer_adresse_symbole(dbg, token);
           if (addr == (unsigned long)-1) {
               printf("Adresse ou symbole invalide\n");
               return;
           }
       }
       if (ajouter_point_arret(dbg, addr)) {
           printf("Point d'arrêt ajouté à 0x%lx\n", addr);
       }
   }
   else if (strcmp(token, "blist") == 0) {
       for (int i = 0; i < dbg->nb_points_arret; i++) {
           printf("%d: 0x%lx\n", 
               dbg->points_arret[i].numero, 
               dbg->points_arret[i].adresse);
       }
   }
   else if (strcmp(token, "bdel") == 0) {
       token = strtok(NULL, " ");
       if (!token) {
           printf("Usage: bdel <numero>\n");
           return;
       }
       int num = atoi(token);
       for (int i = 0; i < dbg->nb_points_arret; i++) {
           if (dbg->points_arret[i].numero == num) {
               restaurer_point_arret(dbg, &dbg->points_arret[i]);
               for (int j = i; j < dbg->nb_points_arret - 1; j++) {
                   dbg->points_arret[j] = dbg->points_arret[j + 1];
               }
               dbg->nb_points_arret--;
               printf("Point d'arrêt %d supprimé\n", num);
               return;
           }
       }
       printf("Point d'arrêt %d non trouvé\n", num);
   }
}

int main(int argc, char *argv[]) {
   if (argc != 2) {
       fprintf(stderr, "Usage: %s <programme>\n", argv[0]);
       return 1;
   }

   struct debogueur dbg = {0};
   
   if (access(argv[1], X_OK) == -1) {
       fprintf(stderr, "Le fichier %s n'existe pas ou n'est pas exécutable\n", argv[1]);
       return 1;
   }

   if (!lire_fichier_elf(argv[1], &dbg.elf)) {
       fprintf(stderr, "Erreur lors de la lecture du fichier ELF\n");
       return 1;
   }

   dbg.nb_points_arret = 0;

   dbg.pid_fils = fork();
   if (dbg.pid_fils == 0) {
       if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
           perror("ptrace");
           exit(1);
       }
       execl(argv[1], argv[1], NULL);
       perror("execl");
       exit(1);
   }
   
   int statut;
   waitpid(dbg.pid_fils, &statut, 0);
   ptrace(PTRACE_SETOPTIONS, dbg.pid_fils, 0, PTRACE_O_EXITKILL);

   char cmd[TAILLE_MAX_CMD];
   while (1) {
       printf("> ");
       fflush(stdout);
       if (!fgets(cmd, sizeof(cmd), stdin)) {
           break;
       }
       traiter_commande(&dbg, cmd);
   }

   free(dbg.elf.debut);
   return 0;
}