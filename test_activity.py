#!/usr/bin/env python3
"""
Test script to simulate file activity that should trigger alerts
Run this in another terminal while the monitor is running
"""

import os
import time
import random
import tempfile

def create_test_files():
    """Create multiple test files to simulate ransomware-like activity"""
    test_dir = "/tmp/ransomware_test"
    os.makedirs(test_dir, exist_ok=True)
    
    print("🧪 Starting ransomware simulation test...")
    print(f"📁 Test directory: {test_dir}")
    
    # Test 1: Multiple file writes (should trigger write threshold)
    print("\n1️⃣ Testing write threshold...")
    files_created = []
    for i in range(10):
        filename = os.path.join(test_dir, f"test_file_{i}.txt")
        with open(filename, "w") as f:
            f.write(f"Test content {i} - " + "A" * 1024)  # 1KB per file
        files_created.append(filename)
        time.sleep(0.1)  # Small delay
    
    print(f"✅ Created {len(files_created)} files")
    time.sleep(2)
    
    # Test 2: Multiple file deletions (should trigger delete threshold)
    print("\n2️⃣ Testing delete threshold...")
    for filename in files_created[:5]:
        os.unlink(filename)
        time.sleep(0.1)
    
    print("✅ Deleted 5 files")
    time.sleep(2)
    
    # Test 3: Large data write (should trigger bytes threshold)
    print("\n3️⃣ Testing bytes threshold...")
    large_file = os.path.join(test_dir, "large_file.dat")
    with open(large_file, "w") as f:
        f.write("X" * (100 * 1024))  # 100KB
    
    print("✅ Created large file (100KB)")
    time.sleep(2)
    
    # Test 4: Simulate encryption behavior (many small file operations)
    print("\n4️⃣ Testing rapid file operations (encryption simulation)...")
    for i in range(15):
        # Create file
        temp_file = os.path.join(test_dir, f"encrypt_test_{i}.doc")
        with open(temp_file, "w") as f:
            f.write("Document content to encrypt")
        
        # Immediately "encrypt" (write different content)
        with open(temp_file, "w") as f:
            f.write("ENCRYPTED_CONTENT_" + str(random.randint(1000, 9999)))
        
        time.sleep(0.05)  # Very rapid operations
    
    print("✅ Simulated encryption of 15 files")
    time.sleep(2)
    
    # Test 5: Create suspicious filenames
    print("\n5️⃣ Testing suspicious filename detection...")
    suspicious_files = [
        "README_FOR_DECRYPT.txt",
        "YOUR_FILES_ARE_ENCRYPTED.txt", 
        "how_to_decrypt_files.txt"
    ]
    
    for filename in suspicious_files:
        filepath = os.path.join(test_dir, filename)
        with open(filepath, "w") as f:
            f.write("Pay bitcoin to decrypt your files!")
        time.sleep(0.5)
    
    print("✅ Created suspicious files")
    
    print(f"\n🧹 Cleaning up test directory: {test_dir}")
    import shutil
    shutil.rmtree(test_dir, ignore_errors=True)
    
    print("✅ Test completed! Check alerts.log for detection results.")

if __name__ == "__main__":
    try:
        create_test_files()
    except KeyboardInterrupt:
        print("\n⏹️ Test interrupted by user")
    except Exception as e:
        print(f"❌ Test failed: {e}")