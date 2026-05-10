# Cyber Atlas - Threat Intelligence Platform

Complete backend implementation for Cyber Atlas, a lightweight OpenCTI-inspired threat intelligence platform.

## 🚀 Features

- **Threat Feed Collection**: Automated collection from URLhaus, OpenPhish, MalwareBazaar, ThreatFox, AlienVault OTX, and AbuseIPDB.
- **IOC Management**: Storing and searching Indicators of Compromise (IPs, Domains, URLs, Hashes).
- **Enrichment**: GeoIP enrichment for IP addresses.
- **Authentication**: JWT-based auth with refresh tokens and API Key support.
- **Security**: Rate limiting, security headers, password policies.
- **Background Tasks**: Celery-based task queue for feed collection and maintenance.

## 🛠️ Technology Stack

- **Framework**: FastAPI (Async Python)
- **Database**: PostgreSQL 16
- **Cache**: Redis 7
- **Search**: OpenSearch 2.11
- **Task Queue**: Celery + Celery Beat

## ⚡ Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for local development)

### Deployment

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cyber_atlas_backend
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and replace all placeholder credentials before starting the services.
   For production, copy `.env.production.example` and generate new passwords/secrets.

3. **Start Services**
   ```bash
   docker-compose up -d
   ```

4. **Access the API**
   - API Documentation: http://localhost:8000/docs
   - Flower (Task Monitor): http://localhost:5555

### 🔑 Default Credentials

> **WARNING**: Change these immediately after first login!

- **Admin Email**: configured by `DEFAULT_ADMIN_EMAIL`
- **Admin Password**: configured by `DEFAULT_ADMIN_PASSWORD`

## 📝 API Usage

### Authentication
Login to get an access token:
```bash
POST /api/auth/login
Content-Type: application/x-www-form-urlencoded

username=admin@cyberatlas.local
password=[YOUR_PASSWORD]
```

### Search IOCs
```bash
GET /api/search/iocs?q=malware&risk_min=8
Authorization: Bearer [ACCESS_TOKEN]
```

### Trigger Feed Pull
```bash
POST /api/feeds/pull
Authorization: Bearer [ACCESS_TOKEN]
```

## 🏗️ Project Structure

```
cyber_atlas_backend/
├── app/
│   ├── core/           # Config, DB, Security
│   ├── models/         # SQLAlchemy Models
│   ├── schemas/        # Pydantic Schemas
│   ├── crud/           # Database Operations
│   ├── routes/         # API Endpoints
│   ├── tasks/          # Celery Tasks & Collectors
│   └── middleware/     # Security Middleware
├── data/               # GeoIP Database (Mounted)
└── logs/               # Application Logs
```

## 🔒 Security Features

- **JWT Authentication**: HS256 with rotation.
- **Rate Limiting**: 100 req/min default, stricter for auth.
- **Security Headers**: HSTS, CSP, X-Frame-Options.
- **Input Validation**: Strict Pydantic models.
- **Container Security**: Non-root user in Docker.

## 🧪 Testing

Run tests locally:
```bash
pip install -r requirements.txt
pytest
```
