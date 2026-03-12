# 🔐 TrustVault: Zero-Trust GDPR-Compliant Storage Platform

**TrustVault** is a high-fidelity prototype of a Zero-Trust secure storage system. It addresses the critical security gap in traditional cloud storage where providers hold the keys to user data. TrustVault ensures that sensitive data is never accessible to the storage provider in an unencrypted state.



## 🤖 Development Methodology: AI-Augmented Engineering
This project was developed using an **AI-augmented workflow**, utilizing Claude AI as a core pair-programmer for rapid prototyping and implementation of complex security patterns.

* **Systems Architecture:** Directed the architectural layout, defining the interaction between the FastAPI backend, OPA policy engine, and PostgreSQL metadata storage.
* **Prompt Engineering:** Orchestrated the generation of complex cryptographic modules (AES-256-GCM), Rego policy files, and the reactive dashboard UI.
* **Integration & Orchestration:** Successfully integrated disparate AI-generated modules into a unified, functional Dockerized environment.
* **Logic Management:** Independently managed the implementation of the **Secure File Sharing** logic and performed end-to-end debugging and system verification.

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

## 📂 Project Structure
```text
trustvault/
├── main.py            # FastAPI Entry Point & Routes
├── auth.py            # JWT & Authentication Logic
├── audit.py           # Immutable Hash-Chain Implementation
├── secure_share.py    # Password-Protected Sharing Logic
├── opa_client.py      # Policy Enforcement Bridge
├── policy.rego        # OPA Policy Rules
└── frontend/          # Vanilla JS Dashboard & UI
<img width="1901" height="913" alt="Screenshot 2026-02-21 002347" src="https://github.com/user-attachments/assets/f63c588c-d17f-4528-81ce-69e449e7969e" />
<img width="1910" height="910" alt="Screenshot 2026-02-21 002405" src="https://github.com/user-attachments/assets/19dcf297-21cb-438b-afe8-1fa874fe9293" />
<img width="1909" height="912" alt="Screenshot 2026-02-21 002623" src="https://github.com/user-attachments/assets/1c1a9481-de13-4671-86d3-34f8e041967f" />
<img width="1911" height="913" alt="Screenshot 2026-02-21 002439" src="https://github.com/user-attachments/assets/9b5416a2-035b-45d8-aa50-de45fd86a234" />
<img width="1900" height="929" alt="Screenshot 2026-02-21 002605" src="https://github.com/user-attachments/assets/30fc7e98-53d0-4d52-8ea5-974d5838f5ca" />
<img width="1902" height="912" alt="Screenshot 2026-02-21 002531" src="https://github.com/user-attachments/assets/7d55241d-6376-4d6b-bbe1-1d1055775f5e" />
<img width="1900" height="910" alt="Screenshot 2026-02-21 002546" src="https://github.com/user-attachments/assets/635a42d4-a483-4db5-80bf-6cfa82cc2027" />
<img width="1908" height="919" alt="Screenshot 2026-02-21 002614" src="https://github.com/user-attachments/assets/2778872a-5ec2-4f44-b9ae-1264c2796d19" />


