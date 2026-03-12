# 🔐 TrustVault: Zero-Trust GDPR-Compliant Storage Platform

**TrustVault** is a high-fidelity prototype of a Zero-Trust secure storage system. It addresses the critical security gap in traditional cloud storage where providers hold the keys to user data. TrustVault ensures that sensitive data is never accessible to the storage provider in an unencrypted state.

## 🖼️ Interface Preview

| Dashboard Overview | Secure File Vault |
| :---: | :---: |
| <img src="https://github.com/user-attachments/assets/f63c588c-d17f-4528-81ce-69e449e7969e" width="400"> | <img src="https://github.com/user-attachments/assets/19dcf297-21cb-438b-afe8-1fa874fe9293" width="400"> |

| Audit Logs (Hash-Chain) | Compliance Reporting |
| :---: | :---: |
| <img src="https://github.com/user-attachments/assets/1c1a9481-de13-4671-86d3-34f8e041967f" width="400"> | <img src="https://github.com/user-attachments/assets/9b5416a2-035b-45d8-aa50-de45fd86a234" width="400"> |

| File Sharing Interface | Secure Upload |
| :---: | :---: |
| <img src="https://github.com/user-attachments/assets/30fc7e98-53d0-4d52-8ea5-974d5838f5ca" width="400"> | <img src="https://github.com/user-attachments/assets/7d55241d-6376-4d6b-bbe1-1d1055775f5e" width="400"> |

| System Settings | GDPR Erasure Flow |
| :---: | :---: |
| <img src="https://github.com/user-attachments/assets/635a42d4-a483-4db5-80bf-6cfa82cc2027" width="400"> | <img src="https://github.com/user-attachments/assets/2778872a-5ec2-4f44-b9ae-1264c2796d19" width="400"> |

---

## 🤖 Development Methodology: AI-Augmented Engineering
This project was developed using an **AI-augmented workflow**, utilizing Claude AI as a core pair-programmer for rapid prototyping and implementation of complex security patterns.

* **Systems Architecture:** Directed the architectural layout, defining the interaction between the FastAPI backend, OPA policy engine, and PostgreSQL metadata storage.
* **Prompt Engineering:** Orchestrated the generation of complex cryptographic modules (AES-256-GCM), Rego policy files, and the reactive dashboard UI.
* **Integration & Orchestration:** Successfully integrated disparate AI-generated modules into a unified, functional Dockerized environment.
* **Logic Management:** Independently managed the implementation of the **Secure File Sharing** logic and performed end-to-end debugging.

## 🏗️ Architecture & Core Principles
TrustVault operates on a **Zero-Knowledge** model. Every request is verified through a strict policy engine before data is retrieved.



* **Security:** `AES-256-GCM` authenticated encryption ensures both privacy and data integrity.
* **Authorization:** Policy-based access control via **Open Policy Agent (OPA)** decouples security logic from business logic.
* **Integrity:** Tamper-proof activity tracking via an **Immutable Hash-Chain Audit Ledger**.



## ✅ Feature Status
| Feature | Implementation Method | Status |
| :--- | :--- | :--- |
| **JWT Authentication** | AI-Augmented / Integrated | ✅ Built |
| **AES-256-GCM Encryption** | AI-Augmented (Crypto Lib) | ✅ Built |
| **OPA Policy Engine** | AI-Augmented (Rego) | ✅ Built |
| **Immutable Audit Ledger** | AI-Augmented (Hash-Chain) | ✅ Built |
| **Secure File Sharing** | Directed Custom Logic | ✅ Built |
| **Deduplication Engine** | AI-Augmented (SHA-256) | ✅ Built |

## ⚙️ Tech Stack
* **Backend:** FastAPI (Python)
* **Database:** PostgreSQL
* **Policy Engine:** OPA (Open Policy Agent)
* **Frontend:** Vanilla JS, CSS, HTML5
* **DevOps:** Docker, Docker Compose

## 🚀 Local Setup
1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/kshetra2627/trust-vault.git](https://github.com/kshetra2627/trust-vault.git)
    cd trust-vault
    ```
2.  **Launch via Docker:**
    ```bash
    docker-compose up -d
    ```
3.  **Access the Dashboard:**
    Open `frontend/index.html` in your browser.

## 🔒 Security & Compliance
* **GDPR Compliance:** Implements a "Right to Erasure" flow that purges both file data and metadata cascades.
* **Hash-Chain Auditing:** Each system event records the SHA-256 hash of the previous event. If a log is altered, the cryptographic chain breaks.
* **Deduplication:** Uses content-addressable storage principles to reduce overhead while maintaining encrypted data silos.

---
**Innovative Hackers** *Hackathon: Zero-Trust GDPR-Compliant Cloud Storage Challenge*
