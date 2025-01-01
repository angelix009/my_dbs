#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct DonneesElf
{
    unsigned char *debut;
    Elf64_Ehdr *entete;
    Elf64_Shdr *table_sections;
    char *table_chaines;
    size_t taille;
};
int lire_fichier(const char *chemin, struct DonneesElf *donnees)
{
    int fd = open(chemin, O_RDONLY);
    if (fd == -1)
        return 0;

    off_t taille_fichier = lseek(fd, 0, SEEK_END);
    if (taille_fichier == -1)
    {
        close(fd);
        return 0;
    }
    donnees->taille = (size_t)taille_fichier;

    if (lseek(fd, 0, SEEK_SET) == -1)
    {
        close(fd);
        return 0;
    }

    donnees->debut = malloc(donnees->taille);
    if (!donnees->debut)
    {
        close(fd);
        return 0;
    }

    size_t total_lu = 0;
    while (total_lu < donnees->taille)
    {
        ssize_t lu =
            read(fd, donnees->debut + total_lu, donnees->taille - total_lu);
        if (lu <= 0)
        {
            free(donnees->debut);
            close(fd);
            return 0;
        }
        total_lu += (size_t)lu;
    }

    close(fd);
    return 1;
}

int initialiser_elf(struct DonneesElf *donnees)
{
    donnees->entete = (Elf64_Ehdr *)donnees->debut;

    if (donnees->taille < sizeof(Elf64_Ehdr))
        return 0;

    if (memcmp(donnees->entete->e_ident, ELFMAG, SELFMAG) != 0)
        return 0;

    donnees->table_sections =
        (Elf64_Shdr *)(donnees->debut + donnees->entete->e_shoff);
    Elf64_Shdr *section_chaines =
        &donnees->table_sections[donnees->entete->e_shstrndx];
    donnees->table_chaines =
        (char *)(donnees->debut + section_chaines->sh_offset);

    return 1;
}

void afficher_symbole(Elf64_Sym *sym, char *strtab, char *shstrtab,
                      Elf64_Shdr *shdr)
{
    printf("%016lx\t%lu\t", sym->st_value, sym->st_size);

    switch (ELF64_ST_TYPE(sym->st_info))
    {
    case STT_NOTYPE:
        printf("STT_NOTYPE\t");
        break;
    case STT_FUNC:
        printf("STT_FUNC\t");
        break;
    case STT_SECTION:
        printf("STT_SECTION\t");
        break;
    default:
        printf("STT_UNKNOWN\t");
    }

    switch (ELF64_ST_BIND(sym->st_info))
    {
    case STB_LOCAL:
        printf("STB_LOCAL\t");
        break;
    case STB_GLOBAL:
        printf("STB_GLOBAL\t");
        break;
    case STB_WEAK:
        printf("STB_WEAK\t");
        break;
    default:
        printf("STB_UNKNOWN\t");
    }

    printf("STV_DEFAULT\t");

    if (sym->st_shndx == SHN_UNDEF)
        printf("UND\t");
    else
        printf("%s\t", shstrtab + shdr[sym->st_shndx].sh_name);

    if (sym->st_name)
        printf("%s", strtab + sym->st_name);

    printf("\n");
}

void afficher_symboles(struct DonneesElf *donnees)
{
    for (size_t i = 0; i < donnees->entete->e_shnum; i++)
    {
        if (donnees->table_sections[i].sh_type == SHT_SYMTAB)
        {
            Elf64_Sym *symboles =
                (Elf64_Sym *)(donnees->debut
                              + donnees->table_sections[i].sh_offset);
            char *strtab =
                (char *)(donnees->debut
                         + donnees
                               ->table_sections[donnees->table_sections[i]
			       .sh_link]
			       .sh_offset);
            size_t nombre_symboles =
                donnees->table_sections[i].sh_size / sizeof(Elf64_Sym);

            for (size_t j = 0; j < nombre_symboles; j++)
            {
                Elf64_Sym *sym = &symboles[j];

                if (ELF64_ST_TYPE(sym->st_info) == STT_FILE)
                    continue;

                afficher_symbole(sym, strtab, donnees->table_chaines,
                                 donnees->table_sections);
            }
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s fichier\n", argv[0]);
        return 1;
    }

    struct DonneesElf donnees = { 0 };

    if (!lire_fichier(argv[1], &donnees))
    {
        fprintf(stderr, "Erreur lors de la lecture du fichier\n");
        return 1;
    }

    if (!initialiser_elf(&donnees))
    {
        fprintf(stderr, "Format ELF invalide\n");
        free(donnees.debut);
        return 1;
    }

    afficher_symboles(&donnees);
    free(donnees.debut);
    return 0;
}
