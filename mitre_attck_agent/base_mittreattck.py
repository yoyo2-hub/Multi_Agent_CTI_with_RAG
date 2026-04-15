import mitreattack
print(f"✅ mitreattack-python version {mitreattack.__version__} is ready!")
import os

def find_mitre_file():
    print("🔎 Searching for enterprise-attack.json...")
    for root, dirs, files in os.walk('input'):
        if "enterprise-attack.json" in files:
            actual_path = os.path.join(root, "enterprise-attack.json")
            print(f"✅ FOUND IT! Use this path in your code:")
            print(f"'{actual_path}'")
            return actual_path
    print("❌ NOT FOUND. Did you click 'Add Data'?")
    return None

correct_path = find_mitre_file()