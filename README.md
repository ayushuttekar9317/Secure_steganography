# 🔐 Secure Image Steganography

A secure image steganography application that allows users to hide confidential text and files inside PNG images using **LSB (Least Significant Bit) steganography** combined with **AES-GCM encryption**.

The project provides a graphical user interface built with **Python and Tkinter**, making secure data hiding accessible without requiring command-line interaction.

---

## 🚀 Features

* 🔐 **AES-GCM Encryption** for protecting hidden data
* 🖼️ **LSB Image Steganography** for hiding encrypted data inside images
* 🔑 **PBKDF2-HMAC-SHA256** for secure password-based key derivation
* 📝 Hide confidential text inside PNG images
* 📁 Hide files inside PNG images
* 🔓 Extract and decrypt hidden information
* 📊 Image quality and steganography analysis
* 🖥️ User-friendly Tkinter graphical interface
* 🛡️ Password-protected data extraction
* 📦 Supports PNG image carriers

---

## 🛠️ Technologies Used

| Technology         | Purpose                       |
| ------------------ | ----------------------------- |
| Python             | Core application development  |
| Tkinter            | Graphical User Interface      |
| Pillow             | Image processing              |
| NumPy              | Image and pixel manipulation  |
| PyCryptodome       | AES-GCM encryption            |
| PBKDF2-HMAC-SHA256 | Password-based key derivation |
| LSB Steganography  | Data hiding                   |

---

## 🔒 Security Architecture

The application uses multiple security layers:

```text
User Data
    │
    ▼
Password
    │
    ▼
PBKDF2-HMAC-SHA256
    │
    ▼
Derived Encryption Key
    │
    ▼
AES-GCM Encryption
    │
    ▼
Encrypted Payload
    │
    ▼
LSB Steganography
    │
    ▼
PNG Image
```

The hidden information is encrypted **before** it is embedded into the image.

Therefore, even if someone successfully extracts the hidden payload, the original data cannot be recovered without the correct password.

---

## 📸 How It Works

### 1. Encode

The user selects:

* A PNG carrier image
* Text or a file to hide
* A password

The application then:

1. Generates a cryptographic salt.
2. Derives an encryption key using PBKDF2-HMAC-SHA256.
3. Encrypts the data using AES-GCM.
4. Creates the payload.
5. Embeds the encrypted payload into the image using LSB steganography.
6. Saves the resulting stego image as a PNG file.

### 2. Decode

The user selects the stego image and enters the password.

The application:

1. Extracts the hidden payload.
2. Reads the cryptographic parameters.
3. Derives the encryption key from the password.
4. Decrypts the payload using AES-GCM.
5. Verifies the authentication tag.
6. Restores the original text or file.

---

## 📊 Steganography Analysis

The project also provides image analysis functionality to evaluate the effect of data hiding.

Analysis includes:

* Mean Squared Error (MSE)
* Peak Signal-to-Noise Ratio (PSNR)
* LSB distribution/balance
* Image capacity
* Payload size

These metrics can be used to evaluate the visual quality and effectiveness of the steganographic process.

---

## 📂 Project Structure

```text
Secure_steganography/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── assets/
│   └── screenshots/
│
└── sample/
    └── sample.png
```

> The exact structure may vary depending on the current version of the project.

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/ayushuttekar9317/Secure_steganography.git
```

### 2. Navigate to the project

```bash
cd Secure_steganography
```

### 3. Create a virtual environment

Windows:

```bash
python -m venv .venv
```

### 4. Activate the virtual environment

Git Bash:

```bash
source .venv/Scripts/activate
```

PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Application

Run:

```bash
python app.py
```

The graphical interface should open automatically.

---

## 🖼️ Screenshots

Add screenshots of the application here.

### Encode

![Encode Interface](assets/screenshots/encode.png)

### Decode

![Decode Interface](assets/screenshots/decode.png)

### Analysis

![Analysis Interface](assets/screenshots/analysis.png)

---

## 🔐 Cryptographic Details

### Encryption

The project uses:

**AES-GCM**

AES-GCM provides both:

* Confidentiality
* Integrity/authentication

### Key Derivation

Passwords are converted into cryptographic keys using:

**PBKDF2-HMAC-SHA256**

A randomly generated salt is used during key derivation to prevent simple precomputed password attacks.

---

## 📋 Requirements

* Python 3.10+
* Pillow
* NumPy
* PyCryptodome
* Tkinter

Install the Python dependencies using:

```bash
pip install -r requirements.txt
```

---

## 🎯 Project Objectives

The main objectives of this project are:

1. Implement image-based steganography.
2. Secure hidden information using modern authenticated encryption.
3. Develop a user-friendly cybersecurity application.
4. Evaluate the impact of data hiding on image quality.
5. Demonstrate the combination of cryptography and steganography.

---

## 🧪 Use Cases

This project can be used for educational and research purposes, including:

* Cybersecurity education
* Information hiding research
* Secure communication experiments
* Digital privacy demonstrations
* Cryptography and steganography studies

---

## ⚠️ Disclaimer

This project is developed for **educational, research, and authorized security testing purposes**.

Users are responsible for ensuring that their use of the application complies with applicable laws and regulations.

---

## 👨‍💻 Author

**Ayush Uttekar**

GitHub:
https://github.com/ayushuttekar9317

---

## ⭐ Support

If you find this project useful, consider giving the repository a ⭐ on GitHub.
