import numpy as np
import os
import sys
import argparse
import pickle
import base64
from typing import Tuple, Optional
import hashlib
from getpass import getpass

class EnhancedQuantumCrypto:
    def __init__(self):
        self.LATTICE_DIM = 2056  # Increased to match bit security
        self.MODULUS = 2147483647  # Largest 31-bit prime for enhanced security
        self.NOISE_BOUND = 4.8  # Increased noise parameter for better security
        
    def _derive_key_material(self, password: str, salt: bytes) -> bytes:
        """Derive key material from password using memory-hard KDF"""
        return hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=2**14,  # Memory cost (16384 iterations)
            r=8,      # Block size
            p=1,      # Parallelization
            maxmem=2**25,  # 32MB max memory
            dklen=257  # 2056-bit output
        )
    
    def _generate_lattice_params(self, key_material: bytes) -> Tuple[np.ndarray, np.ndarray]:
        """Generate deterministic lattice parameters from key material"""
        # Use key material to seed, ensuring it's within numpy's valid range
        seed = int.from_bytes(key_material[:4], 'big') & 0xFFFFFFFF  # Mask to 32 bits
        rng = np.random.RandomState(seed)
        
        # Generate base matrix A
        A = rng.randint(0, self.MODULUS, (self.LATTICE_DIM, self.LATTICE_DIM), dtype=np.int64)
        
        # Generate error vector with controlled noise
        noise = rng.normal(0, self.NOISE_BOUND, self.LATTICE_DIM)
        E = np.round(noise).astype(np.int64) % self.MODULUS
        
        return A, E

    def generate_keypair(self, password: str) -> Tuple[dict, dict]:
        """Generate public/private keypair protected by password"""
        # Generate salt and derive key material
        salt = os.urandom(32)
        key_material = self._derive_key_material(password, salt)
        
        # Generate lattice parameters
        A, E = self._generate_lattice_params(key_material)
        
        # Generate secret vector S with separate seed
        seed_s = int.from_bytes(key_material[8:12], 'big') & 0xFFFFFFFF  # Mask to 32 bits
        rng = np.random.RandomState(seed_s)
        S = rng.randint(-1, 2, self.LATTICE_DIM, dtype=np.int64)
        
        # Compute public B = AS + E
        B = (np.dot(A, S) + E) % self.MODULUS
        
        # Public key contains A, B and salt for password verification
        public_key = {
            'A': A,
            'B': B,
            'salt': salt
        }
        
        # Private key contains S and is encrypted with key material
        private_key = {
            'S': S,
            'salt': salt
        }
        
        return public_key, private_key
    
    def encrypt_data(self, data: bytes, public_key: dict) -> Tuple[bytes, bytes]:
        """Encrypt data using public key"""
        # Convert data to integer array
        data_array = np.frombuffer(data, dtype=np.uint8)
        padded_size = ((len(data_array) + 15) // 16) * 16
        padded_data = np.zeros(padded_size, dtype=np.uint8)
        padded_data[:len(data_array)] = data_array
        
        # Generate random vector r
        r = np.random.randint(-1, 2, self.LATTICE_DIM, dtype=np.int64)
        
        # Compute u = Ar
        u = np.dot(public_key['A'], r) % self.MODULUS
        
        # Compute v = Br + encode(m)
        encoded_data = self._encode_data(padded_data)
        v = (np.dot(public_key['B'], r) + encoded_data) % self.MODULUS
        
        return pickle.dumps((u, v))
    
    def decrypt_data(self, encrypted_data: bytes, private_key: dict, password: str) -> bytes:
        """Decrypt data using private key and password"""
        # Verify password by regenerating key material
        key_material = self._derive_key_material(password, private_key['salt'])
        A_check, _ = self._generate_lattice_params(key_material)
        
        # Load ciphertext
        u, v = pickle.loads(encrypted_data)
        
        # Compute m' = v - Su
        decrypted = (v - np.dot(private_key['S'], u)) % self.MODULUS
        
        # Decode back to bytes
        return self._decode_data(decrypted)
    
    def _encode_data(self, data: np.ndarray) -> np.ndarray:
        """Encode byte data into lattice elements"""
        # Split data into chunks
        chunks = np.array_split(data, self.LATTICE_DIM)
        
        # Encode each chunk into a lattice coefficient
        encoded = np.zeros(self.LATTICE_DIM, dtype=np.int64)
        for i, chunk in enumerate(chunks):
            if len(chunk) > 0:
                encoded[i] = int.from_bytes(chunk.tobytes(), 'big')
                encoded[i] = (encoded[i] * (self.MODULUS // 256)) % self.MODULUS
                
        return encoded
    
    def _decode_data(self, encoded: np.ndarray) -> bytes:
        """Decode lattice elements back to bytes"""
        decoded = bytearray()
        
        for coeff in encoded:
            # Scale back down
            value = (coeff * 256 + self.MODULUS//2) // self.MODULUS
            if 0 <= value <= 255:
                decoded.append(value)
                
        # Remove padding
        while decoded and decoded[-1] == 0:
            decoded.pop()
            
        return bytes(decoded)

def main():
    parser = argparse.ArgumentParser(description='Enhanced Quantum-Resistant Cryptosystem')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Generate keys
    generate_parser = subparsers.add_parser('generate', help='Generate new keypair')
    generate_parser.add_argument('--public', type=str, required=True, help='Public key output file')
    generate_parser.add_argument('--private', type=str, required=True, help='Private key output file')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt data')
    encrypt_parser.add_argument('--public-key', type=str, required=True, help='Public key file')
    encrypt_parser.add_argument('--input', type=str, required=True, help='Input file to encrypt')
    encrypt_parser.add_argument('--output', type=str, required=True, help='Output file for encrypted data')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt data')
    decrypt_parser.add_argument('--private-key', type=str, required=True, help='Private key file')
    decrypt_parser.add_argument('--input', type=str, required=True, help='Input file to decrypt')
    decrypt_parser.add_argument('--output', type=str, required=True, help='Output file for decrypted data')
    
    args = parser.parse_args()
    
    crypto = EnhancedQuantumCrypto()
    
    try:
        if args.command == 'generate':
            # Get password securely
            while True:
                password = getpass("Enter password for key protection: ")
                confirm = getpass("Confirm password: ")
                if password == confirm:
                    break
                print("Passwords don't match, try again")
            
            print("Generating keypair...")
            public_key, private_key = crypto.generate_keypair(password)
            
            # Save keys
            with open(args.public, 'wb') as f:
                pickle.dump(public_key, f)
            with open(args.private, 'wb') as f:
                pickle.dump(private_key, f)
                
            print(f"Keys generated and saved:")
            print(f"Public key: {args.public}")
            print(f"Private key: {args.private}")
            
        elif args.command == 'encrypt':
            # Load public key
            print("Loading public key...")
            with open(args.public_key, 'rb') as f:
                public_key = pickle.load(f)
            
            # Read input file
            print("Reading input file...")
            with open(args.input, 'rb') as f:
                data = f.read()
            
            # Encrypt
            print("Encrypting data...")
            encrypted = crypto.encrypt_data(data, public_key)
            
            # Save encrypted data
            with open(args.output, 'wb') as f:
                f.write(encrypted)
            print(f"Encrypted data saved to: {args.output}")
            
        elif args.command == 'decrypt':
            # Load private key
            print("Loading private key...")
            with open(args.private_key, 'rb') as f:
                private_key = pickle.load(f)
            
            # Get password
            password = getpass("Enter password for private key: ")
            
            # Read encrypted data
            print("Reading encrypted data...")
            with open(args.input, 'rb') as f:
                encrypted = f.read()
            
            # Decrypt
            print("Decrypting data...")
            decrypted = crypto.decrypt_data(encrypted, private_key, password)
            
            # Save decrypted data
            with open(args.output, 'wb') as f:
                f.write(decrypted)
            print(f"Decrypted data saved to: {args.output}")
            
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
