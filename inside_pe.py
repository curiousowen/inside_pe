import pefile

def calculate_entropy(data):
    if len(data) == 0:
        return 0.0
    entropy_value = entropy(data.value_counts(normalize=True), base=2)
    return entropy_value

def print_pe_properties(pe):
    print("PE Sections:")
    for section in pe.sections:
        section_name = section.Name.decode().strip()
        print(f"  Name: {section_name}")
        print(f"    Virtual Address: {section.VirtualAddress}")
        print(f"    Size of Raw Data: {section.SizeOfRawData}")
        print(f"    Characteristics: {hex(section.Characteristics)}")

        # Calculate and print entropy
        data = section.get_data()
        entropy_value = calculate_entropy(data)
        print(f"    Entropy: {entropy_value:.4f}")

    print("\nImported Libraries:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"  {entry.dll.decode()}")  # Print DLL name
        # Print imported functions
        for imp in entry.imports:
            if imp.name:
                print(f"    - {imp.name.decode()}")  # Print function name
            else:
                print(f"    - Ordinal: {imp.ordinal}")  # Print ordinal if no name

if __name__ == "__main__":
    # Replace with the path to your PE file
    pe_file_path = 'pe_file.exe'

    try:
        pe = pefile.PE(pe_file_path)
        print_pe_properties(pe)
    except Exception as e:
        print(f"Error: {e}")
