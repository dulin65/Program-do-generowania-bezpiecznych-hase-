import random
import string
import re
from cryptography.fernet import Fernet
import os
import bcrypt


def generate_key_file(filename='secret.key'):
    try:
        with open(filename, 'rb') as file:
            key = file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(filename, 'wb') as file:
            file.write(key)
    return key

def load_key(filename='secret.key'):
    with open(filename, 'rb') as file:
        key = file.read()
    return key

key = generate_key_file()
cipher_suite = Fernet(key)

def generate_strong_password(length):
    if length < 8:
        raise ValueError("Długość hasła musi wynosić co najmniej 8 znaków.")
    characters = string.ascii_letters + string.digits + string.punctuation
    password = (random.choice(string.ascii_uppercase) + random.choice(string.ascii_lowercase) +
                random.choice(string.digits) + random.choice(string.punctuation))
    password += ''.join(random.choice(characters) for _ in range(length - 4))
    password_list = list(password)
    random.shuffle(password_list)
    return ''.join(password_list)

def is_common_phrase(password):
    common_phrases = ["password", "123456", "qwerty", "letmein", "iloveyou", "asdfghj", "123456789", "qwerty123",
                      "1q2w3e", "111111", "1234567890"]
    return any(phrase in password.lower() for phrase in common_phrases)

def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

def change_password(platform, new_password):
    lines = []
    with open("passwords.txt", "r") as file:
        lines = file.readlines()
    with open("passwords.txt", "w") as file:
        for line in lines:
            if f"Platform: {platform}" in line:
                file.write(f"Platform: {platform}\tPassword: {encrypt_password(new_password)}\n")
            else:
                file.write(line)
def save_password(platform, password):
    encrypted_password = encrypt_password(password)
    with open("passwords.txt", "a") as file:
        file.write(f"Platform: {platform}\tPassword: {encrypted_password}\n")

def read_saved_passwords():
    decrypted_passwords = {}
    with open("passwords.txt", "r") as file:
        for line in file:
            platform, encrypted_password = line.strip().split('\tPassword: ')
            decrypted_password = decrypt_password(encrypted_password)
            decrypted_passwords[platform] = decrypted_password
    return decrypted_passwords

def delete_password(platform):
    """Usuń hasło dla wybranej platformy."""
    is_deleted = False
    with open("passwords.txt", "r") as file:
        lines = file.readlines()
    with open("passwords.txt", "w") as file:
        for line in lines:
            if line.startswith(f"Platform: {platform}"):
                is_deleted = True
                continue  # Pomiń zapisanie tej linii, aby usunąć hasło
            file.write(line)
    return is_deleted

def check_password_strength(password):
    score = 0

    # Długość hasła
    length_score = len(password) // 4  # Za każde 4 znaki hasła, dodaj 1 punkt

    # Małe litery
    if re.search(r'[a-z]', password):
        score += 1

    # Wielkie litery
    if re.search(r'[A-Z]', password):
        score += 1

    # Cyfry
    if re.search(r'[0-9]', password):
        score += 1

    # Znaki specjalne
    if re.search(r'[^a-zA-Z0-9]', password):
        score += 1

    # Sprawdzenie czy hasło zawiera pospolitą frazę
    if is_common_phrase(password):
        score -= 1  # Odejmij punkt za pospolitą frazę

    # Obliczanie końcowego wyniku
    score += length_score  # Dodaj punkty za długość hasła do ogólnego wyniku
    score = max(0, score)  # Zapewnienie, że wynik nie jest mniejszy niż 0

    # Interpretacja wyniku
    if score < 3:
        return 'bardzo słabe'
    elif score < 5:
        return 'słabe'
    elif score < 7:
        return 'średnie'
    elif score < 9:
        return 'dobre'
    else:
        return 'bardzo dobre'

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode(), hashed_password)

def set_or_verify_password(configfile='config'):
    print("Sprawdzanie pliku config...")
    if os.path.exists(configfile):
        with open(configfile, 'rb') as file:
            hashed_password = file.read()
        user_password = input("Wprowadź hasło dostępu do programu: ")
        if not check_password(hashed_password, user_password):
            print("Błędne hasło! Program zostanie zamknięty.")
            exit()
        else:
            print("Hasło poprawne. Kontynuacja działania programu.")
    else:
        print("Plik config nie istnieje. Ustawianie nowego hasła...")
        new_password = input("Ustaw nowe hasło dostępu do programu: ")
        confirm_password = input("Potwierdź hasło: ")
        if new_password == confirm_password:
            with open(configfile, 'wb') as file:
                file.write(hash_password(new_password))
            print("Hasło zostało ustawione.")
        else:
            print("Hasła się różnią. Program zostanie zamknięty.")
            exit()


def main():
    set_or_verify_password()
    while True:
        print("\nOpcje:")
        print("1. Wyświetl zapisane hasła")
        print("2. Zmień hasło dla istniejącej platformy")
        print("3. Dodaj nowe hasło")
        print("4. Usuń wybrane hasło")
        print("5. Sprawdź siłę wprowadzonego hasła")
        print("6. Zakończ program")

        choice = input("Wybierz opcję: ")

        if choice == "1":
            saved_passwords = read_saved_passwords()
            if saved_passwords:
                print("\nZapisane hasła:")
                for platform, password in saved_passwords.items():
                    print(f"Platforma: {platform}, Hasło: {password}")
            else:
                print("Brak zapisanych haseł.")

        elif choice == "2":
            platform_to_change = input("Podaj nazwę platformy, dla której chcesz zmienić hasło: ")
            password_length = int(input("Podaj długość hasła (co najmniej 8 znaków): "))
            while password_length < 8:
                print("Długość hasła musi wynosić co najmniej 8 znaków.")
                password_length = int(input("Podaj poprawną długość hasła: "))
            new_password = generate_strong_password(password_length)
            while is_common_phrase(new_password):
                new_password = generate_strong_password()
            change_password(platform_to_change, new_password)
            print(f"Hasło dla platformy '{platform_to_change}' zostało zmienione.")
            print(f"Twoje nowe hasło dla platformy '{platform_to_change}' to: {new_password}")

        elif choice == "3":
            password_length = int(input("Podaj długość hasła (co najmniej 8 znaków): "))
            while password_length < 8:
                print("Długość hasła musi wynosić co najmniej 8 znaków.")
                password_length = int(input("Podaj poprawną długość hasła: "))
            platform = input("Podaj nazwę platformy, dla której generowane jest hasło: ")
            generated_password = generate_strong_password(password_length)
            while is_common_phrase(generated_password):
                generated_password = generate_strong_password(password_length)
            save_password(platform, generated_password)
            print(f"Twoje wygenerowane hasło dla platformy '{platform}' to: {generated_password}")
            # Wyświetlanie wygenerowanego hasła
            print(f"Hasło dla platformy '{platform}' zostało zapisane.")

        elif choice == "4":  # Dodajemy nową opcję do menu
            platform_to_delete = input("Podaj nazwę platformy, dla której chcesz usunąć hasło: ")
            if delete_password(platform_to_delete):
                print(f"Hasło dla platformy '{platform_to_delete}' zostało usunięte.")
            else:
                print(f"Nie znaleziono hasła dla platformy '{platform_to_delete}'.")

        elif choice == "5":
            password_to_check = input("Wprowadź hasło do sprawdzenia: ")
            strength = check_password_strength(password_to_check)
            print(f"Siła wprowadzonego hasła: {strength}")

        elif choice == "6":
            print("Dziękujemy za skorzystanie z programu.")
            break

        else:
            print("Niepoprawny wybór. Wybierz opcję od 1 do 5.")

if __name__ == "__main__":
    main()