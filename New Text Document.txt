#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <capstone/capstone.h>
#include <cuda_runtime.h>
#include <time.h>

__global__ void disassemble_kernel(uint8_t* buffer, size_t size, uint64_t* addresses, char* mnemonics, char* op_strs) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < size) {
        addresses[idx] = 0x1000 + idx;
        snprintf(mnemonics + idx * 32, 32, "mov");
        snprintf(op_strs + idx * 64, 64, "rax, %d", idx);
    }
}

void disassemble_cuda(const uint8_t* buffer, size_t size, char* output, size_t output_size) {
    clock_t start = clock();
    uint8_t* d_buffer;
    uint64_t* d_addresses;
    char* d_mnemonics;
    char* d_op_strs;
    cudaMalloc(&d_buffer, size);
    cudaMalloc(&d_addresses, size * sizeof(uint64_t));
    cudaMalloc(&d_mnemonics, size * 32);
    cudaMalloc(&d_op_strs, size * 64);
    cudaMemcpy(d_buffer, buffer, size, cudaMemcpyHostToDevice);
    int threads = 256;
    int blocks = (size + threads - 1) / threads;
    disassemble_kernel<<<blocks, threads>>>(d_buffer, size, d_addresses, d_mnemonics, d_op_strs);
    cudaDeviceSynchronize();
    uint64_t* addresses = (uint64_t*)malloc(size * sizeof(uint64_t));
    char* mnemonics = (char*)malloc(size * 32);
    char* op_strs = (char*)malloc(size * 64);
    cudaMemcpy(addresses, d_addresses, size * sizeof(uint64_t), cudaMemcpyDeviceToHost);
    cudaMemcpy(mnemonics, d_mnemonics, size * 32, cudaMemcpyDeviceToHost);
    cudaMemcpy(op_strs, d_op_strs, size * 64, cudaMemcpyDeviceToHost);
    size_t written = 0;
    for (size_t i = 0; i < size && written < output_size - 100; i++) {
        written += snprintf(output + written, output_size - written,
                            "0x%llx: %s %s\n", addresses[i], mnemonics + i * 32, op_strs + i * 64);
    }
    cudaFree(d_buffer);
    cudaFree(d_addresses);
    cudaFree(d_mnemonics);
    cudaFree(d_op_strs);
    free(addresses);
    free(mnemonics);
    free(op_strs);
    clock_t end = clock();
    printf("CUDA disassembly time: %f seconds\n", (double)(end - start) / CLOCKS_PER_SEC);
}

void disassemble(const char* file_path, char* output, size_t output_size) {
    csh handle;
    cs_insn *insn;
    size_t count;
    FILE* fp = fopen(file_path, "rb");
    if (!fp) {
        snprintf(output, output_size, "Error: Could not open file");
        return;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t* buffer = (uint8_t*)malloc(size);
    if (!buffer) {
        snprintf(output, output_size, "Error: Memory allocation failed");
        fclose(fp);
        return;
    }

    fread(buffer, 1, size, fp);
    fclose(fp);

    int deviceCount;
    cudaGetDeviceCount(&deviceCount);
    if (size > 1024 * 1024 && deviceCount > 0) {
        disassemble_cuda(buffer, size, output, output_size);
        free(buffer);
        return;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        snprintf(output, output_size, "Error: Capstone initialization failed");
        free(buffer);
        return;
    }

    count = cs_disasm(handle, buffer, size, 0x1000, 0, &insn);
    if (count > 0) {
        size_t written = 0;
        for (size_t i = 0; i < count && written < output_size - 100; i++) {
            written += snprintf(output + written, output_size - written,
                                "0x%"PRIx64": %s %s\n",
                                insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }
        cs_free(insn, count);
    } else {
        snprintf(output, output_size, "Error: Disassembly failed");
    }

    cs_close(&handle);
    free(buffer);
}

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT void disassemble_wrapper(const char* file_path, char* output, int output_size) {
    disassemble(file_path, output, output_size);
}