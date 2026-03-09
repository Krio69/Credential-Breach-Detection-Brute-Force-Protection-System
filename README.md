# CredShield: Advanced Authentication & Breach Detection System

**Developer:** Kripesh Bhele
**Institution:** Purbanchal University, Nepal
**Course:** Computer Engineering

## 🛡️ Project Overview
CredShield is a "Defense-in-Depth" security platform built with Django and PostgreSQL. Unlike standard authentication systems, CredShield implements proactive security measures to detect leaks, prevent brute-force attacks, and stop session hijacking in real-time.

## 🚀 Key Security Features

### 1. k-Anonymity Breach Detection
* Checks if a user's password has been exposed in known data breaches without ever sending the plain-text password to an external API.
* Uses SHA-1 hashing and range-based queries to maintain user privacy.

### 2. Automated IP "Jailing" (Brute-Force Protection)
* Monitors failed login attempts per IP address.
* If an IP exceeds 10 failed attempts, it is automatically moved to a `BlacklistedIP` table in PostgreSQL.
* Requests from jailed IPs are rejected with a `403 Forbidden` error before hitting the login logic to save server resources.

### 3. Session Fingerprinting & Hijack Prevention
* Captures a unique "fingerprint" (Browser, OS, User-Agent) upon successful login.
* A custom middleware validates this fingerprint on every request. If a session cookie is stolen and used on a different device, the system instantly invalidates the session.

### 4. Dynamic Security Score & Decay
* Provides users with a real-time security health score.
* **Temporal Logic:** The score "decays" over time if a user hasn't rotated their credentials, encouraging better security hygiene.

## 🛠️ Tech Stack
* **Backend:** Python / Django
* **Database:** PostgreSQL (for relational data and GIS-ready spatial support)
* **Frontend:** Tailwind CSS & Vite
* **Security:** k-Anonymity API, Custom Middleware, Risk-Based Authentication
