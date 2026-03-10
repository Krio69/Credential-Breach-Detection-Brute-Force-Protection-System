# CredShield: Advanced Authentication & Breach Detection System

**Developer:** Kripesh Bhele  
**Institution:** Purbanchal University, Nepal  
**Course:** Computer Engineering  

## 🛡️ Project Overview
CredShield is a "Defense-in-Depth" security platform built with Django and PostgreSQL. Unlike standard authentication systems, CredShield implements proactive security measures to detect leaks, prevent brute-force attacks, and stop session hijacking in real-time.

---

## 🚀 Key Security Features

### 1. k-Anonymity Breach Detection
* Integrated with the Pwned Passwords API to check if a user's password has been exposed in public data breaches.
* **Privacy First:** Uses SHA-1 hashing and range-based queries so the plain-text password is never sent over the network.

### 2. Risk-Based Adaptive MFA (SMTP Integration)
* **New IP Detection:** The system monitors the user's login history. If an attempt is made from a new or unrecognized IP address, a mandatory MFA challenge is triggered.
* **Live Email OTP:** Generates a secure 6-digit verification code delivered via **Gmail SMTP** to the user's registered email.



### 3. Automated IP "Jailing" (Brute-Force Protection)
* Monitors failed login attempts per IP address in real-time.
* **Jailing Logic:** If an IP address exceeds 10 failed attempts, it is automatically moved to a `BlacklistedIP` table.
* **Early Rejection:** Requests from jailed IPs are blocked with a `403 Forbidden` response before reaching the application logic, saving database and CPU resources.

### 4. Session Fingerprinting & Hijack Prevention
* Captures a unique "fingerprint" combining the Browser and User-Agent upon successful login.
* Custom middleware validates this fingerprint on every request. If a session cookie is stolen and used on a different device, the system instantly terminates the session.

### 5. Dynamic Security Score & Decay
* Provides users with a real-time security health score (0-100%).
* **Temporal Logic:** The score mathematically "decays" over time (e.g., -5 points every 30 days) if a user hasn't rotated their credentials, encouraging proactive security hygiene.

---

## 🛠️ Tech Stack
* **Backend:** Python 3.x / Django 5.x
* **Database:** PostgreSQL (Neon Serverless)
* **Frontend:** Tailwind CSS
* **Mailing:** Gmail SMTP with Secure App Passwords
* **Deployment:** Vercel (Serverless Functions)


