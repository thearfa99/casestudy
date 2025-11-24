# Vendor Cab and Driver Onboarding: Hierarchical Fleet Management System

## Project Overview
This project demonstrates a robust, Python-based fleet management platform designed for hierarchical vendor networks. It allows a "Super Vendor" (National level) to recruit regional vendors, who can recruit city vendors, creating a recursive management tree. 

The system handles driver/vehicle onboarding, compliance checks, and operational dashboards.

## Key Features
* **N Level Hierarchy:** N-level depth for vendor management (National -> Regional -> City -> Local).
* **Role-Based Access Control (RBAC):** Distinct dashboards for Super Vendors vs. Sub-Vendors.
* **Object-Oriented Architecture (OOP):** Built on strong OOP principles including Inheritance (Vendor inherits SystemUser) and Polymorphism for maintainable, modular code.
* **System Monitoring & Logging:** Integrated real-time system health dashboard that tracks performance metrics and live execution logs (e.g., response times).
* **Resiliency & Fault Tolerance:** Implements automatic Retry Logic with exponential backoff for database failures and custom exception handling for robust error recovery.
* **Performance Optimization (Cost Estimation):** Utilizes TTL Caching and batch queries ($in) to reduce Time Complexity from $O(N^k)$ to $O(N)$.
* **Automated Compliance Engine:** Proactively monitors and flags expirations for Driver Licenses, Vehicle RC, Permits, and Pollution certificates.
* **Architectural Transparency:** dedicated UI tab explicitly documenting system Trade-offs and Time/Space Complexity analysis.
* **Resiliency:** Automatic DB retry logic and transaction safety mechanisms.

## Tech Stack
* **Language:** Python 3.9+
* **Frontend:** Streamlit
* **Database:** MongoDB (Atlas or Local)
* **Libraries:** `pymongo`, `bcrypt`, `pydantic`, `pandas`