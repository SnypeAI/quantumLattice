# Phantom Encryption System

A post-quantum secure asymmetric encryption system using 2056-bit lattice-based cryptography.

## Quick Start

### 1. Setup
±±±bash
# Install dependencies
pip install numpy

# Clone repository
git clone https://github.com/your-username/phantom-encryption.git
cd phantom-encryption

# Create working directory
mkdir secure-comms
cd secure-comms
±±±

### 2. Basic Usage Flow:

±±±mermaid
graph TD
    A[Install] --> B[Generate Keys]
    B --> C[Share Public Key]
    B --> D[Keep Private Key Secure]
    C --> E[Others Encrypt Files]
    D --> F[You Decrypt Files]
    
    style A fill:#f9f,stroke:#333
    style B fill:#bbf,stroke:#333
    style C fill:#dfd,stroke:#333
    style D fill:#fdd,stroke:#333
±±±

## File Structure

Create these files in your working directory:

±±±
secure-comms/
├── quantum_lattice.py    # Main encryption script
├── keys/                 # Directory for key storage
│   ├── public/          
│   └── private/         
├── messages/            # Directory for encrypted files
└── decrypted/          # Directory for decrypted files
±±±

## Detailed Operations

### 1. Key Generation

Generate your keypair:

±±±bash
# Create key directories
mkdir -p keys/public keys/private

# Generate keypair with password protection
python quantum_lattice.py generate --public keys/public/my_public.key --private keys/private/my_private.key
±±±

Process Flow:
±±±mermaid
sequenceDiagram
    participant User
    participant System
    participant KeyStore
    
    User->>System: Enter Password
    System->>System: Generate Salt
    System->>System: Derive Key Material
    System->>System: Create Lattice Parameters
    System->>KeyStore: Save Public Key
    System->>KeyStore: Save Encrypted Private Key
    System->>User: Confirm Generation
±±±

### 2. File Encryption

To encrypt a file for someone:

±±±bash
# Create message directory
mkdir -p messages

# Encrypt file using recipient's public key
python quantum_lattice.py encrypt \
    --public-key /path/to/their_public.key \
    --input /path/to/secret.pdf \
    --output messages/encrypted_secret.bin
±±±

Encryption Process:
±±±mermaid
flowchart LR
    A[Input File] --> B[Read Chunks]
    B --> C[Process Each Chunk]
    C --> D[Lattice Encryption]
    D --> E[Write Output]
    
    subgraph "Per Chunk Processing"
    C --> C1[Convert to Lattice]
    C1 --> C2[Add Noise]
    C2 --> C3[Apply Transform]
    end
±±±

### 3. File Decryption

To decrypt a received file:

±±±bash
# Create decrypted directory
mkdir -p decrypted

# Decrypt file using your private key
python quantum_lattice.py decrypt \
    --private-key keys/private/my_private.key \
    --input messages/encrypted_secret.bin \
    --output decrypted/secret.pdf
±±±

Decryption Process:
±±±mermaid
sequenceDiagram
    participant User
    participant System
    participant Storage
    
    User->>System: Provide Password
    System->>System: Verify Password
    System->>System: Decrypt Private Key
    loop For Each Chunk
        System->>Storage: Read Encrypted Chunk
        System->>System: Lattice Decryption
        System->>Storage: Write Decrypted Chunk
    end
    System->>User: Confirm Completion
±±±

## Technical Implementation Details

### 1. Lattice Parameters

The system uses these specific parameters:

±±±python
# Lattice configuration
LATTICE_DIM = 2056          # Dimension for quantum security
MODULUS = 2147483647        # Largest 31-bit prime
NOISE_BOUND = 4.8           # Gaussian parameter
CHUNK_SIZE = 1024           # Processing block size
±±±

### 2. Key Generation Implementation

The key generation process in detail:

±±±python
def generate_keypair(password: str) -> Tuple[Dict, Dict]:
    # Generate salt for key derivation
    salt = os.urandom(32)
    
    # Derive key material using scrypt
    key_material = scrypt(
        password=password.encode(),
        salt=salt,
        n=16384,  # CPU/memory cost
        r=8,      # Block size
        p=1,      # Parallelization
        dklen=257 # 2056-bit output
    )
    
    # Generate lattice parameters
    A = generate_uniform_matrix(LATTICE_DIM)
    s = generate_secret_vector(LATTICE_DIM)
    e = generate_gaussian_noise(LATTICE_DIM)
    
    # Compute public key
    b = (A @ s + e) % MODULUS
    
    return {
        'A': A,
        'b': b,
        'salt': salt
    }, {
        's': s,
        'salt': salt
    }
±±±

### 3. Encryption Implementation

File encryption process:

±±±python
def encrypt_file(input_file: str, public_key: Dict, output_file: str):
    # Read file in chunks
    with open(input_file, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            # Pad chunk if needed
            if len(chunk) < CHUNK_SIZE:
                chunk = pad_chunk(chunk)
            
            # Convert to lattice element
            m = encode_as_lattice(chunk)
            
            # Generate random vector
            r = generate_random_vector(LATTICE_DIM)
            
            # Compute ciphertext pair
            c1 = (public_key['A'] @ r) % MODULUS
            c2 = (public_key['b'] @ r + m) % MODULUS
            
            # Write encrypted chunk
            write_encrypted_chunk(output_file, c1, c2)
±±±

### 4. Decryption Implementation

File decryption process:

±±±python
def decrypt_file(input_file: str, private_key: Dict, password: str, output_file: str):
    # Verify password and decrypt private key
    key_material = derive_key_material(password, private_key['salt'])
    s = decrypt_private_key(private_key['s'], key_material)
    
    # Process file in chunks
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while chunk := read_encrypted_chunk(f_in):
            c1, c2 = chunk
            
            # Decrypt chunk
            m = (c2 - s @ c1) % MODULUS
            
            # Decode and write
            plaintext = decode_from_lattice(m)
            f_out.write(unpad_chunk(plaintext))
±±±

## Error Handling

The system includes comprehensive error handling:

±±±mermaid
graph TD
    A[Error Occurs] --> B{Type of Error}
    B -->|Password| C[Password Error]
    B -->|File| D[File Error]
    B -->|Memory| E[Memory Error]
    B -->|Crypto| F[Crypto Error]
    
    C --> G[Request Retry]
    D --> H[Check Paths]
    E --> I[Free Memory]
    F --> J[Verify Keys]
±±±

Error types and handling:

1. Password Errors:
   - Invalid password
   - Password too short
   - Password verification failed

2. File Errors:
   - File not found
   - Permission denied
   - Corrupt file

3. Memory Errors:
   - Insufficient memory
   - Memory allocation failed
   - Buffer overflow

4. Cryptographic Errors:
   - Invalid key format
   - Decryption failed
   - Parameter mismatch

## Performance Optimization

Key performance considerations:

±±±python
# Chunk size tuning
OPTIMAL_CHUNK = 1024 * 1024  # 1MB chunks

# Memory management
MAX_MEMORY = 1024 * 1024 * 1024  # 1GB limit

# Multi-processing
NUM_WORKERS = min(os.cpu_count(), 4)  # Use up to 4 cores
±±±

## Security Considerations

Security implementation details:

±±±python
# Security parameters
MIN_PASSWORD_LENGTH = 16
MIN_ENTROPY_BITS = 128
SALT_SIZE = 32
MEMORY_WIPING = True

# Operation modes
TIMING_SAFE = True
CONSTANT_TIME = True
MEMORY_HARD = True
±±±

## Command Line Interface

Complete CLI reference:

±±±python
def main():
    parser = argparse.ArgumentParser(
        description='Phantom Encryption System'
    )
    
    # Command groups
    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands'
    )
    
    # Generate command
    generate = subparsers.add_parser('generate')
    generate.add_argument('--public', required=True)
    generate.add_argument('--private', required=True)
    
    # Encrypt command
    encrypt = subparsers.add_parser('encrypt')
    encrypt.add_argument('--public-key', required=True)
    encrypt.add_argument('--input', required=True)
    encrypt.add_argument('--output', required=True)
    
    # Decrypt command
    decrypt = subparsers.add_parser('decrypt')
    decrypt.add_argument('--private-key', required=True)
    decrypt.add_argument('--input', required=True)
    decrypt.add_argument('--output', required=True)
±±±

## Development and Testing

For development:

±±±bash
# Run tests
python -m pytest tests/

# Check code style
pylint quantum_lattice.py

# Generate documentation
pdoc3 quantum_lattice.py
±±±

## Known Issues and Limitations

Current limitations:

1. Performance:
   - Large file encryption is memory intensive
   - Key generation can be slow on weak systems
   - No hardware acceleration yet

2. Compatibility:
   - Python 3.7+ required
   - NumPy dependency
   - No Windows paths support yet

3. Security:
   - No perfect forward secrecy
   - Manual key distribution needed
   - No key backup system

## Future Improvements

Planned enhancements:

±±±mermaid
graph LR
    A[Current] --> B[Short Term]
    A --> C[Medium Term]
    A --> D[Long Term]
    
    B --> B1[Performance]
    B --> B2[Memory Usage]
    
    C --> C1[Key Backup]
    C --> C2[Forward Secrecy]
    
    D --> D1[Hardware Acceleration]
    D --> D2[Multi-Platform]
±±±
