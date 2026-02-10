# ML Classifier

## Overview
**Model Type:** LightGBM Gradient Boosting Classifier  
**Runtime:** ONNX Runtime (`ort` crate v2.0.0-rc.11)  
**Features:** 27 PE header and structural features  
**Training Data:** ~60,000 samples (Traceix + EMBER datasets)  
**Accuracy:** ~94% on test set (20% holdout)

## Feature Set
The classifier gathers 27 features from PE files using the `goblin` crate. The feature set is based on the dataset provided by the [Traceix AI Security Telemetry](https://huggingface.co/datasets/PerkinsFund/traceix-ai-security-telemetry/tree/main).

### Header Features (20)

| Feature | Type | Description | Example Values |
|---------|------|-------------|----------------|
| `Machine` | u16 | CPU architecture | 332 (I386), 34404 (AMD64) |
| `SizeOfOptionalHeader` | u16 | Optional header size | 224 (32-bit), 240 (64-bit) |
| `Characteristics` | u16 | File characteristics flags | 0x0102 (executable, 32-bit) |
| `MajorLinkerVersion` | u8 | Linker major version | 14 (MSVC 2015+) |
| `MinorLinkerVersion` | u8 | Linker minor version | 0-255 |
| `SizeOfCode` | u32 | Size of .text section | Bytes |
| `SizeOfInitializedData` | u32 | Size of .data section | Bytes |
| `SizeOfUninitializedData` | u32 | Size of .bss section | Bytes |
| `AddressOfEntryPoint` | u32 | Entry point RVA | Offset from image base |
| `BaseOfCode` | u32 | Code section RVA | Offset from image base |
| `ImageBase` | u64 | Preferred load address | 0x400000 (typical) |
| `SectionAlignment` | u32 | Section alignment in memory | 4096 (typical) |
| `FileAlignment` | u32 | Section alignment on disk | 512 (typical) |
| `MajorOperatingSystemVersion` | u16 | Min OS version (major) | 6 (Vista+) |
| `MinorOperatingSystemVersion` | u16 | Min OS version (minor) | 0-255 |
| `SizeOfImage` | u32 | Total image size in memory | Bytes |
| `SizeOfHeaders` | u32 | Combined header size | Bytes |
| `CheckSum` | u32 | PE checksum | 0 (often not set) |
| `Subsystem` | u16 | Target subsystem | 2 (GUI), 3 (CUI) |
| `DllCharacteristics` | u16 | DLL characteristics flags | 0x8160 (typical modern) |

### Section Features (4)

| Feature | Type | Description | Malware Indicator |
|---------|------|-------------|-------------------|
| `SectionsNb` | u32 | Number of sections | Unusual counts (1, 10+) |
| `SectionsMeanEntropy` | f32 | Average entropy across sections | High (>7.0) = packed/encrypted |
| `SectionsMinEntropy` | f32 | Minimum section entropy | Very low (<1.0) = padding |
| `SectionsMaxEntropy` | f32 | Maximum section entropy | Very high (>7.9) = compressed |

### Import/Export Features (3)

| Feature | Type | Description | Malware Indicator |
|---------|------|-------------|-------------------|
| `ImportsNbDLL` | u32 | Number of imported DLLs | Very low (<3) or very high (>20) |
| `ImportsNb` | u32 | Total imported functions | Very low (<10) = packed |
| `ExportNb` | u32 | Number of exported functions | High for EXEs (unusual) |