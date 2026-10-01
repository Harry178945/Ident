# 🔍 IDENT

**Identificateur d'encodages, de bases numériques et de hashs en ligne de commande, façon [dcode.fr](https://www.dcode.fr/).**

Colle une chaîne de caractères mystérieuse : IDENT te dit si c'est du Base64, du hexadécimal, un hash MD5, un JWT, du Morse… avec un score de confiance et un aperçu du texte décodé.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dépendances](https://img.shields.io/badge/d%C3%A9pendances-aucune-brightgreen)
![Licence](https://img.shields.io/badge/licence-MIT-lightgrey)

---

## ✨ Fonctionnalités

- **Un seul fichier**, bibliothèque standard uniquement, aucune installation.
- **Encodages et bases** : Base2, 8, 10, 16, 32 (RFC 4648, Base32hex, Crockford, z-base-32), 36, 45, 58 (avec validation Base58Check), 62, 64 (standard, URL-safe, sans padding), 85 (Ascii85, RFC 1924, Z85), 91.
- **Autres encodages** : URL-encoding, entités HTML, Quoted-Printable, UUencode, séquences `\u` / `\x`, code Morse.
- **Hashs** : MD5, MD4, NTLM, LM, SHA-1, SHA-2, SHA-3, Keccak, RIPEMD, Whirlpool, BLAKE2, CRC32, etc., avec le mode `hashcat` correspondant.
- **Formats à préfixe** : bcrypt, MD5-crypt, SHA-256/512-crypt, phpass, Argon2, PBKDF2, MySQL, PostgreSQL, LDAP, MSSQL, Oracle.
- **Hashs salés** (`hash:sel`) et **digests encodés** en Base64 / Base32.
- **Formats** : JWT (header et payload décodés), UUID, PEM, adresse Ethereum, adresses Bitcoin (Base58Check).
- **Décodage récursif** (`--deep`) : démêle plusieurs couches d'encodage successives.
- **Force brute sur les bases 2 à 62** (`--brute`).
- **Vérification de hash** (`--check`) : confirme l'algorithme exact à partir d'un texte connu.
- **Sortie JSON**, lecture par fichier ou stdin, mode interactif.

## 📦 Installation

```bash
git clone https://github.com/<ton-utilisateur>/ident.git
cd ident
python ident.py --help
```

Python 3.8 ou supérieur. Rien d'autre à installer.

## 🚀 Utilisation

```bash
python ident.py "<chaîne>"
```

### Exemples

**Identifier un encodage**

```console
$ python ident.py "SGVsbG8gV29ybGQ="
Entrée : SGVsbG8gV29ybGQ=
Profil : 16 caractères · entropie 3.45 bits/car. · minuscules, MAJUSCULES, chiffres, symboles
 1. ENCODAGE Base64                          ██████████ 100.0 %
      → Hello World
```

**Identifier un hash**

```console
$ python ident.py 5d41402abc4b2a76b9719d911017c592
 1. HASH     MD5     ███████░░░  67.4 %
      ℹ 32 car. hex (128 bits) · hashcat -m 0
 2. HASH     NTLM    █████░░░░░  49.4 %
      ℹ 32 car. hex (128 bits) · hashcat -m 1000
 3. HASH     MD4     ████░░░░░░  35.9 %
```

**Confirmer l'algorithme avec un texte connu**

```console
$ python ident.py 5d41402abc4b2a76b9719d911017c592 --check hello
✔ Correspondance avec « hello » : md5
```

**Démêler plusieurs couches d'encodage**

```console
$ python ident.py "YzJWamNtVjA=" --deep
Décodage récursif (--deep) :
  couche 1: Base64 (85 %) → c2VjcmV0
  couche 2: Base64 (75 %) → secret
  RÉSULTAT FINAL : secret
```

### Options

| Option | Description |
|---|---|
| `-d`, `--deep` | Décodage récursif multi-couches |
| `-b`, `--brute` | Teste toutes les bases de 2 à 62 (entier → octets) |
| `-c`, `--check TEXTE` | Vérifie si le hash correspond à ce texte et indique l'algorithme |
| `-f`, `--file FICHIER` | Analyse un fichier, une chaîne par ligne |
| `-o`, `--output FICHIER` | Écrit les octets décodés de la meilleure piste (ex. image en Base64) |
| `-n`, `--top N` | Nombre de pistes affichées (défaut : 8) |
| `-m`, `--min-conf N` | Confiance minimale à afficher (défaut : 10) |
| `--json` | Sortie JSON |
| `--no-color` | Désactive les couleurs |
| `--version` | Affiche la version |

Sans argument, l'outil démarre en **mode interactif**. Avec `-`, il lit sur l'entrée standard :

```bash
echo "SGVsbG8=" | python ident.py -
```

### Utilisation comme bibliothèque

```python
import ident

for c in ident.analyze("SGVsbG8gV29ybGQ="):
    print(c.category, c.name, round(c.confidence), c.preview)

ident.deep_decode("YzJWamNtVjA=")            # liste des couches décodées
ident.check_plaintext("5d41402abc4b2a76b9719d911017c592", "hello")   # ['md5']
```

## 🧠 Comment ça marche

Chaque piste reçoit un **score de confiance de 0 à 100**, calculé à partir de deux éléments :

1. **La structure de la chaîne** : alphabet, longueur, padding, canonicité de l'encodage.
2. **Le contenu décodé** : ressemble-t-il à du texte lisible ou à un fichier connu (PNG, PDF, ZIP, GZIP…) ?

Un décodage qui produit du texte propre l'emporte sur un décodage qui produit du binaire aléatoire. Pour la même raison, une chaîne hexadécimale qui décode en texte lisible est classée « hexadécimal » plutôt que « hash ».

Les hashs sont identifiés par leur longueur et leur format, puis pondérés selon leur fréquence d'usage (MD5 et SHA-1 passent avant Tiger-128, par exemple).

## ⚠️ Limites

- Un hash identifié par sa longueur reste une **probabilité** : MD5, NTLM et MD4 ont exactement la même forme. Utilise `--check` avec un texte supposé pour trancher.
- Les chaînes très courtes sont ambiguës par nature (« test » est du Base64 valide).
- IDENT **identifie** les hashs, il ne les casse pas.
- Le mode `--brute` peut produire des faux positifs, d'où le plafond de confiance appliqué.
- Les chiffrements (AES, RSA, César, Vigenère…) ne sont pas gérés : ce ne sont pas des encodages.

## 🧩 Ajouter un format

Écris une fonction qui prend la chaîne et renvoie une liste de tuples `(nom, octets_décodés, score_structure, détails, confiance_forcée)`, puis ajoute-la à la liste `DECODERS` dans `ident.py` :

```python
def dec_monformat(s):
    if not s.startswith("MF:"):
        return []
    return [("Mon format", s[3:].encode(), 0.9, "", None)]

DECODERS.append(dec_monformat)
```

Pour un nouveau hash, ajoute une entrée dans `HEX_HASHES` (par longueur) ou dans `PREFIXED` (par expression régulière).

## 🤝 Contribuer

Les issues et pull requests sont les bienvenues, notamment pour :

- de nouveaux formats de hash ou d'encodage ;
- des cas de test de chaînes mal identifiées ;
- des traductions du README.

## 📄 Licence

MIT. Voir le fichier `LICENSE`.
