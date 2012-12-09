#include <iostream>
#include <string>
#include <elfio/elfio.hpp>

using namespace ELFIO;

int main( int argc, char** argv )
{
    if ( argc != 2 )
    {
        std::cout << "Usage: BinaryTranslator <elf_file>" << std::endl;
        return 1;
    }

    // Create an elfio reader
    elfio reader;

    // Load ELF data
    if ( !reader.load( argv[1] ) )
    {
        std::cout << "Can't find or process ELF file " << argv[1] << std::endl;
        return 2;
    }

    Elf_Half sec_num = reader.sections.size();
    std::string Text = ".text";
    std::cout << "Number of sections: " << sec_num << std::endl;
    for ( int i = 0; i < sec_num; ++i )
    {
        section* psec = reader.sections[i];
        std::cout << "  [" << i << "] "
                  << psec->get_name()
                  << "\t"
                  << psec->get_size()
                  << std::endl;
        // Access to section's data
        const char* p = reader.sections[i]->get_data();
    }

    return 0;
}
