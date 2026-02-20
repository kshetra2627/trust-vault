**🔐 TrustVault — Zero-Trust GDPR-Compliant Cloud Storage Platform**

A zero-trust secure storage platform designed for regulatory compliance (GDPR & ISO/IEC 27001), built with client-side AES-256 encryption, immutable audit logs, and enterprise-grade access control.


**🧠 What is TrustVault?**
TrustVault is a working prototype of a zero-trust secure storage platform that addresses a critical gap in existing cloud storage: provider-controlled encryption and centralized trust models create risks related to key exposure, unauthorized access, and audit manipulation.
This prototype demonstrates client-side AES-256-GCM encryption, JWT-based authentication, OPA policy enforcement, SHA-256 deduplication, and an immutable cryptographic hash-chain audit ledger.
Target use cases: Hospitals storing patient records, financial institutions managing sensitive documents — industries with strict GDPR and audit requirements.

**✅ Features (Prototype)**
Feature                                           Status
-----------------------------------------------------------
JWT Authentication (Login / Register)            ✅Built
-----------------------------------------------------------
Data Region Selection (EU / US / AP)             ✅ Built
-----------------------------------------------------------
AES-256-GCM Client-Side Encryption               ✅ Built
-----------------------------------------------------------
Secure File Upload with Drag & Drop              ✅ Built
-----------------------------------------------------------
SHA-256 Deduplication Engine                     ✅ Built
-----------------------------------------------------------
Immutable Hash-Chain Audit Ledger                ✅ Built
-----------------------------------------------------------
Compliance Reporting Dashboard                   ✅Built
-----------------------------------------------------------
Secure File Share (Password Protected)           ✅ Built
-----------------------------------------------------------
GDPR Right to Erasure                            ✅Built
-----------------------------------------------------------
OPA Zero-Trust Policy Engine                     ✅Built
-----------------------------------------------------------
Dockerized Local Deployment                      ✅ Built
-----------------------------------------------------------
PostgreSQL Metadata Storage                      ✅Built
-----------------------------------------------------------
OAuth 2.0 + MFA + Device Fingerprinting          🔄Planned
-----------------------------------------------------------
AI-Driven Anomaly Detection                      🔄Planned
-----------------------------------------------------------
Automated Compliance Report Export               🔄Planned
-----------------------------------------------------------
Cloud Deployment (Oracle Cloud)                  🔄Planned
-----------------------------------------------------------
Behavioral Analytics Engine                      🔄Planned

**🏗️ Architecture**
Internet Users
      ↓
FastAPI Backend
      ↓
OPA Zero-Trust Policy Engine
      ↓
Client-Side AES-256-GCM Encryption
      ↓
PostgreSQL (Metadata + Audit Logs)
      ↓
Hash Chain Audit Ledger (Tamper Proof)
**Register.py**
<img width="1901" height="913" alt="Screenshot 2026-02-21 002347" src="https://github.com/user-attachments/assets/d16af001-8346-484e-a063-4335ab621dfb" />
**Login**
<img width="1263" height="615" alt="image" src="https://github.com/user-attachments/assets/356bf08a-c912-4818-a227-6efc22267bf1" />

<img width="1909" height="912" alt="Screenshot 2026-02-21 002623" src="https://github.com/user-attachments/assets/702a4dc9-33b8-45b1-8021-5633f3a94ed2" />

<img width="1911" height="913" alt="Screenshot 2026-02-21 002439" src="https://github.com/user-attachments/assets/4adf7ea3-374c-461d-9ce6-ead7c49f3301" />

<img width="1900" height="910" alt="Screenshot 2026-02-21 002546" src="https://github.com/user-attachments/assets/fd49ea2c-c449-4c06-84d0-25cd71558187" />

<img width="1911" height="913" alt="Screenshot 2026-02-21 002439" src="https://github.com/user-attachments/assets/4b29d0d0-408c-4fc9-8da7-3d243f8bb143" />

<img width="1902" height="912" alt="Screenshot 2026-02-21 002531" src="https://github.com/user-attachments/assets/29e28e3a-3974-4c1a-897a-26dbce467cf0" />

<img width="1900" height="929" alt="Screenshot 2026-02-21 002605" src="https://github.com/user-attachments/assets/7c070f84-1773-4b7b-91aa-597bb8c6145b" />

<img width="1908" height="919" alt="Screenshot 2026-02-21 002614" src="https://github.com/user-attachments/assets/0062999e-32eb-4621-9d7b-4680f24cc024" />





**🗂️ Project Structure**
trustvault/
│
├── main.py               # FastAPI backend, all routes
├── auth.py               # JWT authentication
├── database.py           # PostgreSQL connection
├── models.py             # SQLAlchemy models
├── encryption.py         # AES-256-GCM encryption module
├── audit.py              # Immutable hash-chain audit logger
├── secure_share.py       # Password-protected file sharing
├── share_routes.py       # Share API routes
├── schemas.py            # Pydantic schemas
├── security.py           # Security utilities
├── opa_client.py         # OPA policy enforcement client
├── policy.rego           # OPA zero-trust policy rules
├── storage.py            # File storage handler
├── file_service.py       # File business logic
├── docker-compose.yml    # Docker orchestration
├── Dockerfile            # Container definition
├── requirements.txt      # Python dependencies
│
└── frontend/
    └── index.html        # Full UI (Dashboard, Files, Audit, Settings)

⚙️ Tech Stack
Layer                      Technology
--------------------------------------------------------
Backend                   FastAPI (Python)
--------------------------------------------------------
Authentication           JWT (python-jose + bcrypt)
--------------------------------------------------------
Encryption               AES-256-GCM (cryptography lib)
---------------------------------------------------------
Database                 PostgreSQL
---------------------------------------------------------
Policy Engine           OPA (Open Policy Agent)
----------------------------------------------------------
Storage                  Local filesystem
----------------------------------------------------------
Frontend                HTML + CSS + Vanilla JS
-----------------------------------------------------------
Containerization         Docker + Docker Compose

**🚀 Local Setup**
1. Clone the repo
bashgit clone https://github.com/kshetra2627/trust-vault.git
cd trust-vault
**2. Create virtual environment**
bashpython -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/Mac
**3. Install dependencies**
bashpip install -r requirements.txt
**4. Configure environment**
Create a .env file:
DATABASE_URL=postgresql://trustvault:password@localhost/trustvault
SECRET_KEY=your_jwt_secret_key
ALGORITHM=HS256
**5. Start PostgreSQL (Docker)**
bashdocker-compose up -d
**6. Run the backend**
bashuvicorn main:app --host 0.0.0.0 --port 8000 --reload
**7. Open the app**
Open frontend/index.html in your browser or visit http://localhost:8000

**🔒 Security & Compliance**
Requirement                            Implementation
-----------------------------------------------------------------------------------------
GDPR                          Client-side encryption + Right to Erasure endpoint
-----------------------------------------------------------------------------------------
ISO/IEC 27001                Immutable audit logging with hash chain
-----------------------------------------------------------------------------------------
Zero Trust                   JWT authentication + OPA policy engine
-----------------------------------------------------------------------------------------
Data Integrity                SHA-256 hash chain on every audit log entry
------------------------------------------------------------------------------------------
Encryption                   AES-256-GCM, customer-controlled keys
-------------------------------------------------------------------------------------------
Deduplication                 SHA-256 fingerprint with reference counting
--------------------------------------------------------------------------------------------

**📋 API Endpoints**
Method            Endpoint                 Description
-------------------------------------------------------------------------
POST/              register          Create new user account
----------------------------------------------------------------------------
POST/              login             Authenticate and get JWT token
----------------------------------------------------------------------------
POST/             upload           Encrypt and upload file
----------------------------------------------------------------------------
GET                /files          List user's files
----------------------------------------------------------------------------
GET             /download/{hash}   Download encrypted file
----------------------------------------------------------------------------
DELETE         /files/{hash}         Delete file
----------------------------------------------------------------------------
POST           /share-secure      Password-protected file share
----------------------------------------------------------------------------
GET             /audit-logs        View immutable audit trail
----------------------------------------------------------------------------
GET           /compliance-report    Dashboard stats
----------------------------------------------------------------------------
DELETE/gdpr/erase-my-dataGDPR right to erasure
----------------------------------------------------------------------------

**🚀 Future Enhancements
🔐 Security & Authentication
**
OAuth 2.0 + MFA — Replace JWT with OAuth 2.0 and add TOTP-based multi-factor authentication
Device Fingerprinting — Track and verify trusted devices per user session
Continuous Zero-Trust Evaluation — Re-evaluate trust on every request based on behavior, location, and device health
Hardware Security Module (HSM) — Store encryption keys in HSM for maximum key protection

🤖 AI & Threat Intelligence

AI-Driven Anomaly Detection — ML model to detect abnormal download spikes, unusual access times, and privilege escalation attempts
Ransomware Pattern Detection — Identify rapid bulk file modifications typical of ransomware attacks
Behavioral Analytics Engine — Build per-user behavioral baseline and alert on deviations
Automated Threat Response — Auto-suspend accounts showing suspicious activity patterns

📊 Compliance & Reporting

Automated GDPR Report Export — One-click PDF/CSV export of compliance reports for auditors
Data Residency Mapping — Visual map showing exactly where each file is stored geographically
Retention Policy Automation — Auto-delete files after configurable retention periods
ISO 27001 Evidence Pack — Auto-generate audit evidence bundles for certification processes

☁️ Cloud & Infrastructure

Oracle Cloud Deployment — Deploy on Oracle Cloud Always Free VM with public IP
MinIO Distributed Storage — S3-compatible object storage replacing local filesystem
Nginx + HTTPS — Reverse proxy with SSL via Certbot
Resumable Chunk Upload — Split large files into chunks, resume interrupted uploads
Kubernetes Deployment — Replace Docker Compose with Kubernetes for auto-scaling
Multi-Cloud Support — Store across AWS S3, Azure Blob, and Oracle Object Storage

💼 Enterprise Features

Team & Organization Accounts — Multi-user workspaces with role-based access control
SSO Integration — Connect with enterprise identity providers (Okta, Active Directory)
Admin Control Panel — Platform-wide user management, storage quotas, policy enforcement
Webhook Notifications — Alert external systems on file events or policy violations


👥 Team
Team Name: Innovative Hackers
Hackathon: Zero-Trust GDPR-Compliant Cloud Storage Challenge


