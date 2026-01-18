#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>  
#include <sys/stat.h>  
#include <fcntl.h>     
#include <elf.h>       
#include <stdlib.h>    


// ------------ Declarations ------------
struct option {
    char *name;
    void (*handler)();
};

typedef struct {
    int fd;
    void *map_start;
    off_t file_size;
    char filename[256];
} elf_file_t;

// ------------ Globals ------------

int debug_mode;
elf_file_t files[2] = {{-1, NULL, 0, ""}, {-1, NULL, 0, ""}};
int files_count = 2;

// ------------ Menu Handlers ------------
void toggle_debug_mode() {
    if(debug_mode) {
        debug_mode = 0;
        fprintf(stderr, "Debug flag now off\n");
    } else {
        debug_mode = 1;
        fprintf(stderr, "Debug flag now on\n");
    }
}

// ------------ Part 0 -------------

void examine_elf_file() {

    char input_file_name[256];
    printf("Enter ELF file name: ");
    scanf("%s", input_file_name);

    if(debug_mode) {
        fprintf(stderr, "Debug: examining file %s\n", input_file_name);
    }

    int fd = open(input_file_name, O_RDONLY);
    if(fd < 0) {
        perror("Error opening file");
        return;
    }

    if (debug_mode) {
        fprintf(stderr, "Debug: file %s opened successfully\n", input_file_name);
    }

 
    off_t file_size = lseek(fd, 0, SEEK_END);   // Get file size
    lseek(fd, 0, SEEK_SET);

    if (debug_mode) {
        fprintf(stderr, "Debug: File size is %ld bytes\n", (long)file_size);
    }

    

    void *map_start = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_start == MAP_FAILED) {
        perror("Error mapping file");
        close(fd);
        return;
    }

    if (debug_mode) {
        fprintf(stderr, "Debug: File mapped successfully\n");
    }

    int check_if_entered = 0;

    for(int i = 0; i < files_count; i++) {
        if(files[i].fd == -1) {
            check_if_entered = 1;
            files[i].fd = fd;
            files[i].map_start = map_start;
            files[i].file_size = file_size;
            strncpy(files[i].filename, input_file_name, 255);
            break;
        }
    }

    if(!check_if_entered) {
        fprintf(stderr, "Error: Maximum number of files already opened\n");
        munmap(map_start, file_size);
        close(fd);
        return;
    }

    Elf32_Ehdr *header = (Elf32_Ehdr *)map_start;
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        munmap(map_start, file_size);
        close(fd);
        return;
    }

    if(debug_mode) {
        fprintf(stderr, "Debug: Valid ELF file detected\n");
    }

    printf("Magic bytes 1-3: %c%c%c\n", header->e_ident[1], header->e_ident[2], header->e_ident[3]);
    printf("Data encoding: %s\n", header->e_ident[EI_DATA] == 1 ? "2's complement, little endian" : "2's complement, big endian");
    printf("Entry point: 0x%x\n", header->e_entry);
    printf("Section header offset: %d\n", header->e_shoff);
    printf("Number of section headers: %d\n", header->e_shnum);
    printf("Size of section header: %d\n", header->e_shentsize);
    printf("Program header offset: %d\n", header->e_phoff);
    printf("Number of program headers: %d\n", header->e_phnum);
    printf("Size of program header: %d\n", header->e_phentsize);

}

// ------------ Part 0 -------------

// ------------ Part 1 -------------

const char* get_section_type_name(int type) {
    switch (type) {
        case SHT_NULL:     return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB:   return "SYMTAB";
        case SHT_STRTAB:   return "STRTAB";
        case SHT_RELA:     return "RELA";
        case SHT_HASH:     return "HASH";
        case SHT_DYNAMIC:  return "DYNAMIC";
        case SHT_NOTE:     return "NOTE";
        case SHT_NOBITS:   return "NOBITS";
        case SHT_REL:      return "REL";
        case SHT_SHLIB:    return "SHLIB";
        case SHT_DYNSYM:   return "DYNSYM";
        case SHT_GNU_verdef:      return "VERDEF";
        case SHT_GNU_verneed:     return "VERNEED";
        case SHT_GNU_versym:      return "VERSYM";
        default:                  return "UNKNOWN";
    }
}

void print_section_names() {
    for (int i = 0; i < files_count; i++) {
        if (files[i].fd == -1) continue;

        printf("File %s\n", files[i].filename);
        Elf32_Ehdr *header = (Elf32_Ehdr *)files[i].map_start;
        
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)(files[i].map_start + header->e_shoff);
        
        Elf32_Shdr *shstrtab_header = &shdr_table[header->e_shstrndx];
        char *shstrtab_ptr = (char *)(files[i].map_start + shstrtab_header->sh_offset);

        if (debug_mode) {
            fprintf(stderr, "Debug: shstrndx: %d, shstrtab offset: 0x%x\n", 
                    header->e_shstrndx, shstrtab_header->sh_offset);
        }

        printf("[%2s] %-20s %-10s %-10s %-10s %-10s\n", 
               "id", "name", "address", "offset", "size", "type");

        for (int j = 0; j < header->e_shnum; j++) {
            char *name = shstrtab_ptr + shdr_table[j].sh_name;
    
            printf("[%2d] %-20s %08x   %08x   %08x   %-15s\n",
                j,
                name,
                shdr_table[j].sh_addr,
                shdr_table[j].sh_offset,
                shdr_table[j].sh_size,
                get_section_type_name(shdr_table[j].sh_type));
        }
    }
}

// ------------ Part 1 -------------

// ------------ Part 2 -------------

void print_symbols() {
    for (int i = 0; i < files_count; i++) {
        if (files[i].fd == -1) continue;
        printf("File %s\n", files[i].filename);

        Elf32_Ehdr *header = (Elf32_Ehdr *)files[i].map_start;
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)(files[i].map_start + header->e_shoff);
        
        Elf32_Shdr *shstrtab_header = &shdr_table[header->e_shstrndx];
        char *shstrtab_ptr = (char *)(files[i].map_start + shstrtab_header->sh_offset);

        for (int j = 0; j < header->e_shnum; j++) {
            if (shdr_table[j].sh_type == SHT_SYMTAB) {
                
                Elf32_Sym *sym_table = (Elf32_Sym *)(files[i].map_start + shdr_table[j].sh_offset);
                int num_symbols = shdr_table[j].sh_size / shdr_table[j].sh_entsize;
                
                char *strtab_ptr = (char *)(files[i].map_start + shdr_table[shdr_table[j].sh_link].sh_offset);

                if (debug_mode) {
                    fprintf(stderr, "Debug: Found symbol table size: %d, symbols: %d\n", 
                            shdr_table[j].sh_size, num_symbols);
                }

                printf("[%2s] %-8s %-6s %-15s %-20s\n", "id", "value", "s_idx", "section_name", "symbol_name");

                for (int k = 0; k < num_symbols; k++) {
                    char *symbol_name = strtab_ptr + sym_table[k].st_name;
                    char *sec_name;
                    
                    if (sym_table[k].st_shndx == SHN_UNDEF) sec_name = "UND";
                    else if (sym_table[k].st_shndx == SHN_ABS) sec_name = "ABS";
                    else if (sym_table[k].st_shndx < header->e_shnum) {
                        sec_name = shstrtab_ptr + shdr_table[sym_table[k].st_shndx].sh_name;
                    } else sec_name = "UNKNOWN";

                    printf("[%2d] %08x %-6d %-15s %-20s\n", 
                           k, sym_table[k].st_value, sym_table[k].st_shndx, sec_name, symbol_name);
                }
            }
        }
    }
}

const char* get_relocation_type_name(int type) {
    switch (type) {
        case R_386_NONE:      return "R_386_NONE";
        case R_386_32:        return "R_386_32";
        case R_386_PC32:      return "R_386_PC32";
        case R_386_GOT32:     return "R_386_GOT32";
        case R_386_PLT32:     return "R_386_PLT32";
        case R_386_COPY:      return "R_386_COPY";
        case R_386_GLOB_DAT:  return "R_386_GLOB_DAT";
        case R_386_JMP_SLOT:  return "R_386_JMP_SLOT";
        case R_386_RELATIVE:  return "R_386_RELATIVE";
        case R_386_GOTOFF:    return "R_386_GOTOFF";
        case R_386_GOTPC:     return "R_386_GOTPC";
        default:              return "UNKNOWN";
    }
}

void print_relocations() {
    for (int i = 0; i < files_count; i++) {
        if (files[i].fd == -1) continue;
        printf("File %s\n", files[i].filename);

        Elf32_Ehdr *header = (Elf32_Ehdr *)files[i].map_start;
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)(files[i].map_start + header->e_shoff);
        int found_rel = 0;

        for (int j = 0; j < header->e_shnum; j++) {
            if (shdr_table[j].sh_type == SHT_REL) {
                found_rel = 1;
                Elf32_Rel *rel_table = (Elf32_Rel *)(files[i].map_start + shdr_table[j].sh_offset);
                int num_relocs = shdr_table[j].sh_size / shdr_table[j].sh_entsize;

                Elf32_Shdr *symtab_hdr = &shdr_table[shdr_table[j].sh_link];
                Elf32_Sym *sym_table = (Elf32_Sym *)(files[i].map_start + symtab_hdr->sh_offset);
                int num_symbols = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
                
                char *strtab_ptr = (char *)(files[i].map_start + shdr_table[symtab_hdr->sh_link].sh_offset);

                if (debug_mode) {
                    fprintf(stderr, "Debug: Found Relocation section at offset 0x%x\n", shdr_table[j].sh_offset);
                    fprintf(stderr, "Debug: Associated symbol table size: %d, symbols: %d\n", 
                            symtab_hdr->sh_size, num_symbols);
                }

                printf("[%2s] %-10s %-20s %-5s %-5s\n", "id", "location", "symbol_name", "size", "type");

                for (int k = 0; k < num_relocs; k++) {
                    int sym_idx = ELF32_R_SYM(rel_table[k].r_info);
                    int rel_type = ELF32_R_TYPE(rel_table[k].r_info);
                    char *symbol_name = strtab_ptr + sym_table[sym_idx].st_name;

                    printf("[%2d] %08x   %-20s %-5d %-15s\n", 
                           k, rel_table[k].r_offset, symbol_name, 4, get_relocation_type_name(rel_type));
                }
            }
        }
        if (!found_rel) {
            printf("No relocations\n");
        }
    }
}

// ------------ Part 2 -------------

// ------------ Part 3 -------------

void check_files_for_merge() {
    if (files[0].fd == -1 || files[1].fd == -1) {
        printf("Error: Two ELF files must be opened and mapped first.\n");
        return;
    }

    Elf32_Ehdr *ehdr1 = (Elf32_Ehdr *)files[0].map_start;
    Elf32_Ehdr *ehdr2 = (Elf32_Ehdr *)files[1].map_start;
    Elf32_Shdr *shdr1 = (Elf32_Shdr *)(files[0].map_start + ehdr1->e_shoff);
    Elf32_Shdr *shdr2 = (Elf32_Shdr *)(files[1].map_start + ehdr2->e_shoff);

    Elf32_Shdr *symtab1_hdr = NULL, *symtab2_hdr = NULL;
    for (int i = 0; i < ehdr1->e_shnum; i++) {
        if (shdr1[i].sh_type == SHT_SYMTAB) symtab1_hdr = &shdr1[i];
    }
    for (int i = 0; i < ehdr2->e_shnum; i++) {
        if (shdr2[i].sh_type == SHT_SYMTAB) symtab2_hdr = &shdr2[i];
    }

    if (!symtab1_hdr || !symtab2_hdr) {
        printf("feature not supported\n");
        return;
    }

    Elf32_Sym *syms1 = (Elf32_Sym *)(files[0].map_start + symtab1_hdr->sh_offset);
    Elf32_Sym *syms2 = (Elf32_Sym *)(files[1].map_start + symtab2_hdr->sh_offset);
    char *strs1 = (char *)(files[0].map_start + shdr1[symtab1_hdr->sh_link].sh_offset);
    char *strs2 = (char *)(files[1].map_start + shdr2[symtab2_hdr->sh_link].sh_offset);

    int num_syms1 = symtab1_hdr->sh_size / symtab1_hdr->sh_entsize;
    int num_syms2 = symtab2_hdr->sh_size / symtab2_hdr->sh_entsize;

    for (int k = 1; k < num_syms1; k++) { 
        char *name = strs1 + syms1[k].st_name;
        if (strlen(name) == 0) continue;

        int found_idx = -1;
        for (int m = 1; m < num_syms2; m++) {
            if (strcmp(name, strs2 + syms2[m].st_name) == 0) {
                found_idx = m;
                break;
            }
        }

        if (syms1[k].st_shndx == SHN_UNDEF) {
            if (found_idx == -1 || syms2[found_idx].st_shndx == SHN_UNDEF) {
                printf("Symbol %s undefined\n", name);
            }
        }
        else {
            if (found_idx != -1 && syms2[found_idx].st_shndx != SHN_UNDEF) {
                printf("Symbol %s multiply defined\n", name);
            }
        }
    }

    for (int k = 1; k < num_syms2; k++) {
        char *name = strs2 + syms2[k].st_name;
        if (strlen(name) == 0) continue;

        int found_idx = -1;
        for (int m = 1; m < num_syms1; m++) {
            if (strcmp(name, strs1 + syms1[m].st_name) == 0) {
                found_idx = m;
                break;
            }
        }

        if (syms2[k].st_shndx == SHN_UNDEF) {
            if (found_idx == -1 || syms1[found_idx].st_shndx == SHN_UNDEF) {
                printf("Symbol %s undefined\n", name);
            }
        }
    }

    if (debug_mode) {
        fprintf(stderr, "Debug: CheckMerge completed for %s and %s\n", files[0].filename, files[1].filename);
    }
}

void merge_elf_files() {
    
    if (files[0].fd == -1 || files[1].fd == -1) {
        printf("Error: Two ELF files must be opened first.\n");
        return;
    }

    int out_fd = open("out.ro", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("Error creating out.ro");
        return;
    }

    Elf32_Ehdr *ehdr1 = (Elf32_Ehdr *)files[0].map_start;
    Elf32_Ehdr *ehdr2 = (Elf32_Ehdr *)files[1].map_start;
    Elf32_Shdr *shdr1 = (Elf32_Shdr *)(files[0].map_start + ehdr1->e_shoff);
    Elf32_Shdr *shdr2 = (Elf32_Shdr *)(files[1].map_start + ehdr2->e_shoff);
    char *shstrtab1 = (char *)(files[0].map_start + shdr1[ehdr1->e_shstrndx].sh_offset);

    Elf32_Ehdr new_ehdr = *ehdr1;
    Elf32_Shdr *new_shdr_table = malloc(ehdr1->e_shnum * sizeof(Elf32_Shdr));
    memcpy(new_shdr_table, shdr1, ehdr1->e_shnum * sizeof(Elf32_Shdr));

    write(out_fd, &new_ehdr, sizeof(Elf32_Ehdr));

    for (int i = 0; i < ehdr1->e_shnum; i++) {
        if (i == 0) continue; 

        char *sec_name = shstrtab1 + shdr1[i].sh_name;
        
        new_shdr_table[i].sh_offset = lseek(out_fd, 0, SEEK_CUR);

        if (strcmp(sec_name, ".text") == 0 || strcmp(sec_name, ".data") == 0 || strcmp(sec_name, ".rodata") == 0) {
            
            write(out_fd, files[0].map_start + shdr1[i].sh_offset, shdr1[i].sh_size);
            
            int found_in_2 = -1;
            char *shstrtab2 = (char *)(files[1].map_start + shdr2[ehdr2->e_shstrndx].sh_offset);
            for (int j = 0; j < ehdr2->e_shnum; j++) {
                if (strcmp(sec_name, shstrtab2 + shdr2[j].sh_name) == 0) {
                    found_in_2 = j;
                    break;
                }
            }

            if (found_in_2 != -1) {
                write(out_fd, files[1].map_start + shdr2[found_in_2].sh_offset, shdr2[found_in_2].sh_size);
                new_shdr_table[i].sh_size = shdr1[i].sh_size + shdr2[found_in_2].sh_size;
            }
        } 
        else {
            write(out_fd, files[0].map_start + shdr1[i].sh_offset, shdr1[i].sh_size);
            new_shdr_table[i].sh_size = shdr1[i].sh_size;
        }
    }

    off_t shoff = lseek(out_fd, 0, SEEK_CUR);
    write(out_fd, new_shdr_table, ehdr1->e_shnum * sizeof(Elf32_Shdr));

    new_ehdr.e_shoff = shoff;
    lseek(out_fd, 0, SEEK_SET);
    write(out_fd, &new_ehdr, sizeof(Elf32_Ehdr));

    free(new_shdr_table);
    close(out_fd);
    printf("Merge completed successfully into out.ro\n");
}

// ------------ Part 3 -------------

void quit(){
    if(debug_mode){
        fprintf(stderr, "Debug: quitting\n");
    }

    for(int i = 0; i < files_count; i++){
        if(files[i].fd != -1){
            munmap(files[i].map_start, files[i].file_size);
            close(files[i].fd);
            if(debug_mode){
                fprintf(stderr, "Debug: closed file %s\n", files[i].filename);
            }
        }
    }

    exit(0);
}


// ------------ Functions ------------

int main(int argc, char *argv[]) {
    
    struct option menu[] = {
        {"Toggle Debug Mode", toggle_debug_mode},
        {"Examine ELF File", examine_elf_file},
        {"Print Section Names", print_section_names},
        {"Print Symbols", print_symbols},
        {"Print Relocations", print_relocations},
        {"Check Files for Merge", check_files_for_merge},
        {"Merge ELF Files", merge_elf_files},
        {"Quit", quit},
        {NULL, NULL}
    };

    debug_mode = 0; // Initialize debug mode to off

    while(1){

        printf("Choose action:\n"); // Print menu
        int i = 0;
        while (menu[i].name != NULL){
            printf("%d- %s\n", i, menu[i].name);
            i++;
        }

        int choice = -1; // Get user choice
        scanf("%d", &choice);
        if(feof(stdin)){
            break;
        }
        for(i = 0; menu[i].name != NULL; i++){
            if(i == choice){
                menu[i].handler(); // Call the chosen handler
                break;
            }
        }
    }

    return 0;
}