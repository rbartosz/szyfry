import os
import math
import csv
from collections import Counter
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# ==========================================
# 1. PRZYGOTOWANIE FOLDERU WYNIKOWEGO
# ==========================================
FOLDER_WYNIKOWY = "pliki"
os.makedirs(FOLDER_WYNIKOWY, exist_ok=True)


# ==========================================
# 2. FUNKCJE POMOCNICZE
# ==========================================

def oblicz_entropie(tekst):
    if not tekst: return 0.0
    czestotliwosc = Counter(tekst)
    dlugosc = len(tekst)
    entropia = 0.0
    for ilosc in czestotliwosc.values():
        prawdopodobienstwo = ilosc / dlugosc
        entropia -= prawdopodobienstwo * math.log2(prawdopodobienstwo)
    return entropia


def format_excel(liczba):
    """Formatowanie dla polskiego Excela (przecinek zamiast kropki)."""
    return str(round(liczba, 4)).replace('.', ',')


# ==========================================
# 3. GENEROWANIE KLUCZY I SZYFROWANIE
# ==========================================

print("Generowanie kluczy...")
rsa_key = RSA.generate(2048)
rsa_public_key = rsa_key.publickey()
rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
aes_key = get_random_bytes(16)
cezar_przesuniecie = 3

# Zmieniona nazwa zmiennej na przestawieniowy_klucz
przestawieniowy_klucz = [3, 0, 4, 1, 5, 2, 8, 6, 9, 7]

# Zapis kluczy do folderu 'pliki'
path_klucze = os.path.join(FOLDER_WYNIKOWY, "klucze.txt")
with open(path_klucze, "w", encoding="utf-8") as pk:
    pk.write(f"Cezar: {cezar_przesuniecie}\nPermutacja: {przestawieniowy_klucz}\n")
    pk.write(f"AES (HEX): {aes_key.hex()}\n")
    pk.write(f"RSA Public:\n{rsa_public_key.export_key().decode()}\n")


# Funkcje szyfrujące
def szyfruj_cezar(t, p):
    w = ""
    for z in t:
        if z.isalpha():
            s = 65 if z.isupper() else 97
            w += chr((ord(z) - s + p) % 26 + s)
        else:
            w += z
    return w


def szyfruj_przestawieniowy(t, k):
    reszta = len(t) % 10
    if reszta != 0: t += " " * (10 - reszta)
    w = ""
    for i in range(0, len(t), 10):
        b = t[i:i + 10]
        w += "".join([b[j] for j in k])
    return w


def szyfruj_aes(t, k):
    s = AES.new(k, AES.MODE_EAX)
    c, tag = s.encrypt_and_digest(t.encode('utf-8'))
    return f"{s.nonce.hex()}:{c.hex()}"


def szyfruj_rsa(t, s):
    return s.encrypt(t.encode('utf-8')[:190]).hex()


# ==========================================
# 4. PRZETWARZANIE 10 PLIKÓW
# ==========================================

print(f"Przetwarzanie... Wyniki trafia do folderu: {FOLDER_WYNIKOWY}")

path_csv = os.path.join(FOLDER_WYNIKOWY, "zestawienie_entropii.csv")
with open(path_csv, "w", newline="", encoding="utf-8") as f_csv:
    writer = csv.writer(f_csv, delimiter=';')
    # Zmieniony nagłówek w Excelu
    writer.writerow(["Plik", "Jawny", "Cezar", "Przestawieniowy", "AES", "RSA"])

    for i in range(1, 11):
        nazwa_wejscia = f"plik{i}.txt"

        try:
            with open(nazwa_wejscia, 'r', encoding='utf-8') as f:
                tresc = f.read()
        except FileNotFoundError:
            print(f"Brak pliku {nazwa_wejscia}")
            continue

        # Szyfrowanie
        c_cezar = szyfruj_cezar(tresc, cezar_przesuniecie)
        # Zmieniona nazwa zmiennej wynikowej
        c_przestawieniowy = szyfruj_przestawieniowy(tresc, przestawieniowy_klucz)
        c_aes = szyfruj_aes(tresc, aes_key)
        c_rsa = szyfruj_rsa(tresc, rsa_cipher)

        # Zapisywanie 5 plików dla każdego zestawu do folderu 'pliki'
        with open(os.path.join(FOLDER_WYNIKOWY, f"plik{i}.txt"), 'w', encoding='utf-8') as f:
            f.write(tresc)
        with open(os.path.join(FOLDER_WYNIKOWY, f"cezar{i}.txt"), 'w', encoding='utf-8') as f:
            f.write(c_cezar)
        # Zmieniona nazwa tworzonego pliku tekstowego na przestawieniowy{i}.txt
        with open(os.path.join(FOLDER_WYNIKOWY, f"przestawieniowy{i}.txt"), 'w', encoding='utf-8') as f:
            f.write(c_przestawieniowy)
        with open(os.path.join(FOLDER_WYNIKOWY, f"aes{i}.txt"), 'w', encoding='utf-8') as f:
            f.write(c_aes)
        with open(os.path.join(FOLDER_WYNIKOWY, f"rsa{i}.txt"), 'w', encoding='utf-8') as f:
            f.write(c_rsa)

        # Entropia
        writer.writerow([
            f"Zestaw {i}",
            format_excel(oblicz_entropie(tresc)),
            format_excel(oblicz_entropie(c_cezar)),
            format_excel(oblicz_entropie(c_przestawieniowy)),  # Podmiana zmiennej
            format_excel(oblicz_entropie(c_aes)),
            format_excel(oblicz_entropie(c_rsa))
        ])
        print(f"Gotowe: Zestaw {i}")

print("\nSukces! Folder 'pliki' zawiera teraz komplet 50 plików i raport.")