
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend

def generate_dh_shared_secret():
    # Generación de claves privada y pública
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Obtener la clave pública
    public_key = private_key.public_key()

    # Guardar la clave pública en un archivo dhss.pem en la misma ubicación
    with open("dhss.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ))

    print("Public key saved to: dhss.pem")

def check_file_existence(file_path):
    if os.path.exists(file_path):
        print(f"El archivo {file_path} existe.")
    else:
        print(f"El archivo {file_path} no se ha encontrado.")

if __name__ == "__main__":
    generate_dh_shared_secret()

    # Verificar la ubicación actual
    current_dir = os.getcwd()
    print(f"Current directory: {current_dir}")

    # Verificar la existencia del archivo dhss.pem
    file_path = "dhss.pem"
    check_file_existence(file_path)


