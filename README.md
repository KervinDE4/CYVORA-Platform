
# CYVORA

**An AI-powered cybersecurity and digital protection platform.**

CYVORA is being developed to help individuals and organisations identify, understand, report and respond to digital threats through an integrated cybersecurity platform.

## Platform Modules

1. **ThreatScan** – Analyse suspicious URLs, messages, screenshots and documents for potential threats.
2. **CallTrust** – Check phone numbers and claimed institutional identities against a directory of verified contacts.
3. **Report** – Submit suspicious activities and cybercrime reports for review.
4. **SecureScore** – Assess cybersecurity awareness and security practices.
5. **Academy** – Access cybersecurity learning materials, lessons and quizzes.
6. **Command** – Central dashboard for users, administrators, alerts and platform analytics.

## Technology Stack

- Frontend: React, TypeScript and Vite
- Backend: Python, Django and Django REST Framework
- Database: PostgreSQL through Supabase
- Authentication: Supabase Auth
- Version control: Git and GitHub

## Project Structure

```text
CYVORA-Platform/
├── backend/
├── database/
├── datasets/
├── docs/
├── frontend/
├── security/
├── tests/
├── .env.example
├── CONTRIBUTING.md
├── README.md
└── SECURITY.md
```

## Development

CYVORA is under active development. Features, integrations and security controls are being implemented incrementally.

For development guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

For security-related information, see [SECURITY.md](SECURITY.md).

## Important Security Note

CallTrust directory matches are reference checks, not proof of caller identity. Phone number matching alone cannot prevent caller-ID spoofing.

## Project Status

Under active development.
