from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Gerar par de chaves (pública e privada)
def gerar_chaves():
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    chave_publica = chave_privada.public_key()

    # Salvar chave privada
    with open("chave_privada.pem", "wb") as f:
        f.write(
            chave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Salvar chave pública
    with open("chave_publica.pem", "wb") as f:
        f.write(
            chave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Carregar chave pública
def carregar_chave_publica():
    with open("chave_publica.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

# Carregar chave privada
def carregar_chave_privada():
    with open("chave_privada.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# Criptografar com chave pública
def criptografar(mensagem: str, chave_publica) -> bytes:
    return chave_publica.encrypt(
        mensagem.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Descriptografar com chave privada
def descriptografar(mensagem_cifrada: bytes, chave_privada) -> str:
    return chave_privada.decrypt(
        mensagem_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

# Exemplo de uso
if __name__ == "__main__":
    gerar_chaves()  # Gera e salva as chaves

    chave_pub = carregar_chave_publica()
    chave_priv = carregar_chave_privada()

    mensagem = "Informação super secreta!"
    mensagem_cifrada = criptografar(mensagem, chave_pub)
    print("Mensagem cifrada:", mensagem_cifrada)

    mensagem_original = descriptografar(mensagem_cifrada, chave_priv)
    print("Mensagem original:", mensagem_original)

    # ✅ Verificação final
    assert mensagem == mensagem_original
    print("✅ Verificação OK: A mensagem foi restaurada com sucesso!")
