import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from skl2onnx import to_onnx, update_registered_converter
from skl2onnx.common.shape_calculator import calculate_linear_classifier_output_shapes
from skl2onnx.common.data_types import FloatTensorType
from onnxmltools.convert.lightgbm.operator_converters.LightGbm import convert_lightgbm
import json
import glob
import os

DATA_DIR = "data"
MODEL_OUTPUT = "model.onnx"

SUBSYSTEM_MAP = {
    'WINDOWS_GUI': 2,
    'WINDOWS_CUI': 3,
    'NATIVE': 1,
    'UNKNOWN': 0,
    'OS2_CUI': 5,
    'POSIX_CUI': 7,
    'NATIVE_WINDOWS': 8,
    'WINDOWS_CE_GUI': 9,
    'EFI_APPLICATION': 10,
    'EFI_BOOT_SERVICE_DRIVER': 11,
    'EFI_RUNTIME_DRIVER': 12,
    'EFI_ROM': 13,
    'XBOX': 14,
    'WINDOWS_BOOT_APPLICATION': 16
}

MACHINE_MAP = {
    'I386': 332,
    'AMD64': 34404,
    'UNKNOWN': 0
}

def clean_dataset(df):
    """
    Sanitizes the dataframe to ensure all features are numeric.
    Handles string labels like 'WINDOWS_GUI' -> 2.
    """
    # 1. Map known string columns if they exist
    if 'Subsystem' in df.columns:
        # Replace dictionary keys with values, ignore others for now
        df['Subsystem'] = df['Subsystem'].replace(SUBSYSTEM_MAP)
    
    if 'Machine' in df.columns:
        df['Machine'] = df['Machine'].replace(MACHINE_MAP)

    # 2. Force convert everything to numeric
    # errors='coerce' turns "UnknownString" into NaN (0) instead of crashing
    for col in df.columns:
        if col != 'label':
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    return df





def load_data(data_dir):
    all_data = []
    files = glob.glob(os.path.join(data_dir, "*.jsonl"))
    
    print(f"Found {len(files)} dataset files: {files}")
    
    for file_path in files:
        print(f"Loading {file_path}...")
        with open(file_path, 'r') as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    features = obj.get('decrypted_training_data')
                    if not features: 
                        continue

                    # Handle labels
                    # Traceix: inside 'model_classification_info'
                    # EMBER (Converted): We put 'label' inside 'decrypted_training_data' in previous script 
                    # OR wrapped it. Let's handle both.
                    
                    label = -1
                    if 'label' in features:
                         label = features['label']
                    elif 'model_classification_info' in obj:
                        cls = obj['model_classification_info']['identified_class']
                        label = 1 if cls == 'malicious' else 0
                    
                    if label != -1:
                        # Remove label from features to avoid leakage
                        features_clean = features.copy()
                        if 'label' in features_clean: 
                            del features_clean['label']
                        
                        features_clean['label'] = label
                        all_data.append(features_clean)
                except Exception as e:
                    continue
                    
    return pd.DataFrame(all_data)

print("Loading Datasets...")
df = load_data(DATA_DIR)
print(f"Total records: {len(df)}")
print(f"Class distribution:\n{df['label'].value_counts()}")

if len(df) < 100:
    print("WARNING: Dataset is still very small. Results may be unstable.")

print("Sanitizing data (converting strings to integers)...")
df = clean_dataset(df)

df = df.fillna(0)

print(f"Class distribution:\n{df['label'].value_counts()}")
feature_order = [
    "Machine", "SizeOfOptionalHeader", "Characteristics", 
    "MajorLinkerVersion", "MinorLinkerVersion", 
    "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData", 
    "AddressOfEntryPoint", "BaseOfCode", 
    "ImageBase", "SectionAlignment", "FileAlignment", 
    "MajorOperatingSystemVersion", "MinorOperatingSystemVersion", 
    "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics", 
    "SectionsNb", "SectionsMeanEntropy", "SectionsMinEntropy", "SectionsMaxEntropy", 
    "ImportsNbDLL", "ImportsNb", "ExportNb"
]

# Ensure we only use columns that exist in the dataframe
valid_features = [f for f in feature_order if f in df.columns]

X = df[valid_features].astype('float32')
y = df['label']

print("Training LightGBM...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = lgb.LGBMClassifier(
    n_estimators=500, 
    learning_rate=0.05, 
    num_leaves=31,
    n_jobs=-1
)
model.fit(X_train, y_train)

preds = model.predict(X_test)
acc = accuracy_score(y_test, preds)
print(f"Accuracy: {acc:.4f}")
print(classification_report(y_test, preds))

print("Exporting to ONNX with ZipMap DISABLED...")

# 1. Register the converter
update_registered_converter(
    lgb.LGBMClassifier, 
    'LightGbmClassifier', 
    calculate_linear_classifier_output_shapes, 
    convert_lightgbm, 
    options={'nocl': [True, False], 'zipmap': [True, False, 'columns']}
)

# 2. Define the input type explicitly
#    Name: 'float_input' (Must match your Rust code!)
#    Shape: [None, 27] (Batch size x Number of Features)
initial_types = [('float_input', FloatTensorType([None, X.shape[1]]))]

# 3. Convert
onnx_model = to_onnx(
    model, 
    initial_types=initial_types,
    options={'zipmap': False}, 
    target_opset={'': 12, 'ai.onnx.ml': 3} 
)

# 4. Save
with open("model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print("Model saved to model.onnx")