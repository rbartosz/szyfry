import os
import math
from collections import Counter
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


# ==========================================
# 1. FUNKCJA MATEMATYCZNA: ENTROPIA SHANNONA
# ==========================================

def oblicz_entropie(tekst):
    """Oblicza entropię Shannona dla podanego ciągu znaków."""
    if not tekst:
        return 0.0

    czestotliwosc = Counter(tekst)  # Zlicza wystąpienia każdego znaku
    dlugosc = len(tekst)
    entropia = 0.0

    for ilosc in czestotliwosc.values():
        prawdopodobienstwo = ilosc / dlugosc
        # Wzór Shannona: sumujemy -p * log2(p)
        entropia -= prawdopodobienstwo * math.log2(prawdopodobienstwo)

    return entropia


# ==========================================
# 2. GENEROWANIE KLUCZY I USTAWIEŃ
# ==========================================

print("Generowanie kluczy kryptograficznych...")

rsa_key = RSA.generate(2048)
rsa_public_key = rsa_key.publickey()
rsa_cipher = PKCS1_OAEP.new(rsa_public_key)

aes_key = get_random_bytes(16)
cezar_przesuniecie = 3
trans_klucz = [3, 0, 4, 1, 5, 2, 8, 6, 9, 7]

# ------------------------------------------
# ZAPIS KLUCZY DO PLIKU
# ------------------------------------------
print("Zapisywanie kluczy do pliku klucze.txt...")
with open("klucze.txt", "w", encoding="utf-8") as plik_kluczy:
    plik_kluczy.write("=== KLUCZE KRYPTOGRAFICZNE ===\n\n")

    plik_kluczy.write("1. Szyfr Cezara:\n")
    plik_kluczy.write(f"Przesuniecie: {cezar_przesuniecie}\n\n")

    plik_kluczy.write("2. Szyfr Przestawieniowy (Permutacja):\n")
    plik_kluczy.write(f"Kolejnosc (Klucz): {trans_klucz}\n\n")

    plik_kluczy.write("3. Szyfr AES (Tryb EAX):\n")
    plik_kluczy.write(f"Klucz (HEX): {aes_key.hex()}\n\n")

    plik_kluczy.write("4. Szyfr RSA:\n")
    plik_kluczy.write("Klucz Prywatny (PEM):\n")
    plik_kluczy.write(rsa_key.export_key().decode('utf-8') + "\n\n")
    plik_kluczy.write("Klucz Publiczny (PEM):\n")
    plik_kluczy.write(rsa_public_key.export_key().decode('utf-8') + "\n")


# ==========================================
# 3. FUNKCJE SZYFRUJĄCE (z poprzedniego kroku)
# ==========================================

def szyfruj_cezar(tekst, przesuniecie):
    wynik = ""
    for znak in tekst:
        if znak.isalpha():
            ascii_start = 65 if znak.isupper() else 97
            nowy_znak = chr((ord(znak) - ascii_start + przesuniecie) % 26 + ascii_start)
            wynik += nowy_znak
        else:
            wynik += znak
    return wynik


def szyfruj_przestawieniowy(tekst, klucz):
    rozmiar_bloku = 10
    wynik = ""
    reszta = len(tekst) % rozmiar_bloku
    if reszta != 0:
        tekst += " " * (rozmiar_bloku - reszta)
    for i in range(0, len(tekst), rozmiar_bloku):
        blok = tekst[i: i + rozmiar_bloku]
        wynik += "".join([blok[j] for j in klucz])
    return wynik


def szyfruj_aes(tekst, klucz):
    szyfrator = AES.new(klucz, AES.MODE_EAX)
    nonce = szyfrator.nonce
    ciphertext, tag = szyfrator.encrypt_and_digest(tekst.encode('utf-8'))
    return f"{nonce.hex()}:{ciphertext.hex()}"


def szyfruj_rsa(tekst, szyfrator):
    dane_w_bajtach = tekst.encode('utf-8')
    zaszyfrowane_bajty = szyfrator.encrypt(dane_w_bajtach)
    return zaszyfrowane_bajty.hex()


# ==========================================
# 4. PĘTLA GŁÓWNA - PRZETWARZANIE I ENTROPIA
# ==========================================

print("Rozpoczynam przetwarzanie plików i badanie entropii...")

# Otwieramy plik do zapisywania raportu z entropii
with open("raport_entropii.txt", "w", encoding="utf-8") as raport:
    raport.write("=== RAPORT ENTROPII SHANNONA ===\n")

    for i in range(1, 11):
        nazwa_pliku = f"plik{i}.txt"

        # Generowanie pliku testowego, jeśli nie istnieje
        if not os.path.exists(nazwa_pliku):
            with open(nazwa_pliku, 'w', encoding='utf-8') as f:
                f.write(
                    f"To jest przykladowy tekst w pliku numer {i} do zaszyfrowania. Posiada rozne znaki, aby entropia miala co liczyc!")

        with open(nazwa_pliku, 'r', encoding='utf-8') as f:
            tresc = f.read()

        # Szyfrowanie
        cezar = szyfruj_cezar(tresc, cezar_przesuniecie)
        trans = szyfruj_przestawieniowy(tresc, trans_klucz)
        aes = szyfruj_aes(tresc, aes_key)
        rsa = szyfruj_rsa(tresc[:190], rsa_cipher)  # Ograniczenie dla RSA

        # Zapis szyfrogramów do plików
        with open(f"cezar{i}.txt", 'w', encoding='utf-8') as f:
            f.write(cezar)
        with open(f"trans{i}.txt", 'w', encoding='utf-8') as f:
            f.write(trans)
        with open(f"aes{i}.txt", 'w', encoding='utf-8') as f:
            f.write(aes)
        with open(f"rsa{i}.txt", 'w', encoding='utf-8') as f:
            f.write(rsa)

        # Obliczanie entropii
        ent_jawny = oblicz_entropie(tresc)
        ent_cezar = oblicz_entropie(cezar)
        ent_trans = oblicz_entropie(trans)
        ent_aes = oblicz_entropie(aes)
        ent_rsa = oblicz_entropie(rsa)

        # Zapis wyników do raportu
        raport.write(f"\n--- Plik: {nazwa_pliku} ---\n")
        raport.write(f"Tekst jawny:      {ent_jawny:.4f} bitów/znak\n")
        raport.write(f"Szyfr Cezara:     {ent_cezar:.4f} bitów/znak\n")
        raport.write(f"Przestawieniowy:  {ent_trans:.4f} bitów/znak\n")
        raport.write(f"AES (format hex): {ent_aes:.4f} bitów/znak\n")
        raport.write(f"RSA (format hex): {ent_rsa:.4f} bitów/znak\n")

print("Sukces! Wygenerowano pliki 'klucze.txt' oraz 'raport_entropii.txt'.")