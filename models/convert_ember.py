# attempts to map the ember dataset to the format in the traceix output (script fully provided by gemini)
import glob
import json
import numpy as np
import os

EMBER_FOLDER = "data/ember2018/" # Path to your downloaded EMBER JSONL
OUTPUT_FILE = "data/ember_converted.jsonl"

def calculate_entropy(sections):
    if not sections:
        return 0.0, 0.0, 0.0
    entropies = [s['entropy'] for s in sections]
    return np.mean(entropies), min(entropies), max(entropies)

def map_ember_to_traceix(ember_entry):
    """
    Maps a raw EMBER feature dictionary to the Traceix flat schema.
    """
    try:
        header = ember_entry.get('header', {})
        coff = header.get('coff', {})
        optional = header.get('optional', {})
        sections = ember_entry.get('section', {}).get('sections', [])
        imports = ember_entry.get('imports', {})
        exports = ember_entry.get('exports', [])
        
        # Calculate Aggregates
        sec_mean_ent, sec_min_ent, sec_max_ent = calculate_entropy(sections)
        
        # Count imports
        # EMBER 'imports' is a dict: { "dll_name": ["func1", "func2"], ... }
        imports_nb_dll = len(imports)
        imports_nb = sum(len(funcs) for funcs in imports.values())

        # Flattened Object
        traceix_obj = {
            # Standard Headers
            "Machine": coff.get('machine', 0) if isinstance(coff.get('machine'), int) else 0, # Sometimes string in newer LIEF
            "SizeOfOptionalHeader": coff.get('size_of_optional_header', 0),
            "Characteristics": coff.get('characteristics', 0) if isinstance(coff.get('characteristics'), int) else 0,
            
            "MajorLinkerVersion": optional.get('major_linker_version', 0),
            "MinorLinkerVersion": optional.get('minor_linker_version', 0),
            "SizeOfCode": optional.get('size_of_code', 0),
            "SizeOfInitializedData": optional.get('size_of_initialized_data', 0),
            "SizeOfUninitializedData": optional.get('size_of_uninitialized_data', 0),
            "AddressOfEntryPoint": optional.get('address_of_entry_point', 0),
            "BaseOfCode": optional.get('base_of_code', 0),
            "ImageBase": optional.get('image_base', 0),
            "SectionAlignment": optional.get('section_alignment', 0),
            "FileAlignment": optional.get('file_alignment', 0),
            "MajorOperatingSystemVersion": optional.get('major_operating_system_version', 0),
            "MinorOperatingSystemVersion": optional.get('minor_operating_system_version', 0),
            "SizeOfImage": optional.get('size_of_image', 0),
            "SizeOfHeaders": optional.get('size_of_headers', 0),
            "CheckSum": optional.get('checksum', 0),
            "Subsystem": optional.get('subsystem', 0),
            "DllCharacteristics": optional.get('dll_characteristics', 0),

            # Derived Metrics
            "SectionsNb": len(sections),
            "SectionsMeanEntropy": sec_mean_ent,
            "SectionsMinEntropy": sec_min_ent,
            "SectionsMaxEntropy": sec_max_ent,
            
            "ImportsNbDLL": imports_nb_dll,
            "ImportsNb": imports_nb,
            "ExportNb": len(exports),
            
            # Label (Traceix uses 'label' in training wrapper, but we put it here for consistency)
            "label": ember_entry.get('label', -1) 
        }
        
        # Filter out unlabeled data (-1 in EMBER)
        if traceix_obj['label'] == -1:
            return None
            
        return traceix_obj

    except Exception as e:
        # print(f"Error parsing entry: {e}")
        return None
    
def main():
    
    # Get all jsonl files in the folder
    ember_files = glob.glob(os.path.join(EMBER_FOLDER, "*.jsonl"))
    
    if not ember_files:
        print(f"Error: No .jsonl files found in {EMBER_FOLDER}")
        return

    print(f"Found {len(ember_files)} files to convert.")
    total_count = 0

    with open(OUTPUT_FILE, 'w') as f_out:
        for file_path in ember_files:
            print(f"Processing {os.path.basename(file_path)}...")
            file_count = 0
            with open(file_path, 'r') as f_in:
                for line in f_in:
                    try:
                        ember_data = json.loads(line)
                        mapped = map_ember_to_traceix(ember_data)
                        
                        if mapped:
                            wrapper = {
                                "model_classification_info": {
                                    "identified_class": "malicious" if mapped['label'] == 1 else "benign"
                                },
                                "decrypted_training_data": mapped
                            }
                            f_out.write(json.dumps(wrapper) + "\n")
                            file_count += 1
                    except:
                        continue
            print(f"  -> Converted {file_count} records.")
            total_count += file_count
                
    print(f"Done! Saved total of {total_count} records to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()