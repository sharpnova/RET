#include <pybind11/pybind11.h>
#include <memory>
#include <string>
#include <fstream>
#include <stdexcept>
#include <ghidra_bridge.hpp>

std::string decompile(const std::string& file_path) {
    try {
        auto file = std::make_unique<std::ifstream>(file_path, std::ios::binary);
        if (!file->is_open()) {
            throw std::runtime_error("Could not open file");
        }

        file->seekg(0, std::ios::end);
        size_t size = file->tellg();
        file->close();

        GhidraBridge bridge;
        std::string script = R"(
            from ghidra.program.model.listing import FunctionIterator
            functions = currentProgram.getFunctionManager().getFunctions(True)
            result = []
            for func in functions:
                result.append(f"Function: {func.getName()}\n{func.getBody()}")
            print('\n'.join(result))
        )";
        std::string result = bridge.remote_exec(script, file_path);
        return result.empty() ? "Decompiled " + std::to_string(size) + " bytes" : result;
    } catch (const std::exception& e) {
        return "Error: " + std::string(e.what());
    }
}

PYBIND11_MODULE(libanalyzer, m) {
    m.def("decompile", &decompile, "Decompile a binary file with Ghidra");
}