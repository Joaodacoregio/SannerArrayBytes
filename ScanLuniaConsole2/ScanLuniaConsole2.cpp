 #include <windows.h>
#include <iostream>
#include <iomanip>
#include <atomic>
#include <cstring>
#include <vector>  // Para usar std::vector

#define PATTERN_SIZE 80
#define BLOCK_SIZE 524288      // 512kb para o primeiro escaneamento
#define SMALL_BLOCK_SIZE 4096   // 4 KB para o segundo escaneamento

std::atomic<uint64_t> found_address(0); // Armazena o primeiro endereço encontrado de maneira segura
std::atomic<bool> address_found(false); // Indica se o endereço foi encontrado para interromper o escaneamento
std::vector<uint64_t> found_addresses; // Usando um vetor para armazenar múltiplos endereços encontrados

unsigned char pattern[PATTERN_SIZE] = {
    0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Função para comparar a memória lida com o padrão desejado
bool compare_memory(const unsigned char* data, const unsigned char* pattern, size_t pattern_size) {
    return memcmp(data, pattern, pattern_size) == 0;
}

// Função de escaneamento inicial para encontrar o primeiro endereço correspondente
void find_pattern_in_memory(HANDLE process, uint64_t start_address, uint64_t end_address) {
    unsigned char buffer[BLOCK_SIZE];
    SIZE_T bytesRead;

    for (uint64_t address = start_address; address < end_address && !address_found; address += BLOCK_SIZE) {
        SIZE_T bytes_to_read = min(BLOCK_SIZE, end_address - address);

        // Verifica se a leitura de memória foi bem-sucedida
        if (ReadProcessMemory(process, (LPCVOID)address, buffer, bytes_to_read, &bytesRead)) {
            for (size_t i = 0; i <= bytesRead - PATTERN_SIZE && !address_found; i++) {
                if (compare_memory(&buffer[i], pattern, PATTERN_SIZE)) {
                    found_address = address + i;
                    address_found = true;
                    break;
                }
            }
        }
    }
}

// Função de escaneamento refinado, realizada ao redor do endereço encontrado
void refine_scan_until_end_of_range(HANDLE process, uint64_t base_address) {
    unsigned char small_buffer[SMALL_BLOCK_SIZE];
    SIZE_T bytesRead;

    uint64_t range_start = (base_address & 0xFFF00000000);
    uint64_t range_limit = (base_address & 0xF0000000000) | 0xFFFFFFFFFF;

    // Ajustando a condição do loop para garantir que não ultrapasse o limite do intervalo
    for (uint64_t addr = range_start; addr < range_limit; addr += SMALL_BLOCK_SIZE) {
        // Lê a memória do processo
        if (ReadProcessMemory(process, (LPCVOID)addr, small_buffer, SMALL_BLOCK_SIZE, &bytesRead)) {
            // Garante que não acesse fora dos limites do buffer
            for (size_t i = 0; i <= bytesRead - PATTERN_SIZE; i++) {
                if (compare_memory(&small_buffer[i], pattern, PATTERN_SIZE)) {
                    uint64_t refined_address = addr + i;

                    // Adiciona o endereço encontrado ao vetor
                    found_addresses.push_back(refined_address);
                }
            }
        }
    }
}

int main() {
    DWORD pid;
    std::cout << "Digite o ID do processo (PID): ";
    std::cin >> pid;

    // Abre o processo para leitura
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (process != NULL) {
        uint64_t start_address = 0x0000010000000000;
        uint64_t end_address = 0x000002FFFFFFFFFF;

        // Primeiro escaneamento para localizar o padrão
        std::cout << "Iniciando primeiro escaneamento...\n";
        find_pattern_in_memory(process, start_address, end_address);

        // Se o endereço foi encontrado, executa o escaneamento refinado
        if (address_found) {
            std::cout << "Iniciando segundo escaneamento refinado...\n";

            // Carrega o valor atômico de found_address para evitar conflitos de tipo
            uint64_t address_to_refine = found_address.load();

            // Chama a função de escaneamento refinado diretamente
            refine_scan_until_end_of_range(process, address_to_refine);

            // Mostra quantos padrões foram encontrados
            std::cout << "Padrões encontrados: " << found_addresses.size() << std::endl;

            // Exibe os endereços encontrados
            for (const auto& addr : found_addresses) {
                std::cout << std::hex << "Endereço encontrado: " << addr << std::endl;
            }
        }
        else {
            std::cout << "Padrão não encontrado no primeiro escaneamento." << std::endl;
        }

        CloseHandle(process);
    }
    else {
        std::cerr << "Falha ao abrir o processo. Verifique o PID e tente novamente." << std::endl;
    }

    std::cout << "\nEscaneamento concluído. Pressione qualquer tecla para sair..." << std::endl;
    std::cin.ignore();
    std::cin.get();

    return 0;
}

 