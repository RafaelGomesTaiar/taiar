from cryptography.fernet import Fernet

# Gerar uma chave simétrica
def gerar_chave():
    chave = Fernet.generate_key()
    with open("chave.key", "wb") as chave_arquivo:
        chave_arquivo.write(chave)
    return chave

# Carregar chave de um arquivo
def carregar_chave():
    with open("chave.key", "rb") as chave_arquivo:
        return chave_arquivo.read()

# Criptografar dados
def criptografar(mensagem: str, chave: bytes) -> bytes:
    f = Fernet(chave)
    return f.encrypt(mensagem.encode())

# Descriptografar dados
def descriptografar(mensagem_cifrada: bytes, chave: bytes) -> str:
    f = Fernet(chave)
    return f.decrypt(mensagem_cifrada).decode()

# Exemplo de uso
if __name__ == "__main__":
    chave = gerar_chave()  # ou use carregar_chave() se a chave já existir
    mensagem = "Segredo muito importante!"

    mensagem_cifrada = criptografar(mensagem, chave)
    print("Mensagem cifrada:", mensagem_cifrada)

    mensagem_original = descriptografar(mensagem_cifrada, chave)
    print("Mensagem original:", mensagem_original)

    # ✅ Verificação final
    assert mensagem == mensagem_original
    print("✅ Verificação OK: A mensagem foi restaurada com sucesso!")
