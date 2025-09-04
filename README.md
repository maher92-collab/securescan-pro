# SecureScan Pro

SecureScan Pro is a security scanning tool I’ve built for checking networks and web apps. It has a FastAPI backend and React frontend, with a clean modern UI (dark mode, glass style) that matches the design I had in mind.

👉 Live Demo: [SecureScan Pro](https://securescan-pro-49m9.onrender.com/)

Main interface
<img width="1911" height="912" alt="main interface" src="https://github.com/user-attachments/assets/3738ab22-a4eb-4b48-8fe8-57beb9e60e09" />

Scanning in Progress
<img width="1914" height="918" alt="scanning in progress" src="https://github.com/user-attachments/assets/be4f428d-a646-459a-a6a3-4be1acfac577" />

Security report
<img width="1907" height="913" alt="security report 1" src="https://github.com/user-attachments/assets/939443dd-aaf3-4d17-9b07-cc693ea41ea1" />

SecureScan Pro - Security Assessment Report

## Why I Built This
I wanted to learn more about network security while practicing full-stack development. This project let me explore both frontend React development and backend security concepts in a practical way.

##  Main Features

- Port scanning (TCP) – Finds open ports and grabs banners
- HTTP header check – Looks for missing or weak security headers
- TLS/SSL analysis – Spots outdated protocols, weak ciphers, and certificate issues
- CVE mapping – Links detected services to known vulnerabilities
- Quick or deep scans – Run fast scans or go more detailed if you’ve got the time
- Modern UI – Dark theme, glassmorphism, smooth interface
- Reports – Export results to PDF or JSON

- Live progress – See scan results as they happen
- REST API – Full API support with documentation

## 🏗️ Architecture

```
React Frontend ↔ FastAPI Backend ↔ Redis Cache
     ↓               ↓               ↓
     └─── Security Scanner Engine ───┘
```

## 🚀 Quick Start

### Using Docker Compose 

```bash

git clone https://github.com/maher92-collab/securescan-pro.git
cd securescan-pro


docker-compose up -d


open http://localhost:8000
```

### Manual Installation

#### Backend Setup

```bash

pip install -r requirements.txt


redis-server


uvicorn app.main:app --reload
```

#### Frontend Setup

```bash
cd frontend

npm install

npm start
```

## 📚 API Documentation

### Start Scan
```http
POST /scan
Content-Type: application/json

{
  "target": "example.com",
  "scan_type": "quick|deep",
  "components": [
    "tcp_port_scanning",
    "http_security_headers", 
    "tls_ssl_analysis",
    "cve_vulnerability_mapping"
  ]
}
```

### Get Scan Status
```http
GET /scan/{job_id}
```

### Download Reports
```http
GET /report/{job_id}.pdf
GET /report/{job_id}.json
```

## 🧪 Testing

### Backend Tests
```bash

# Run all tests with coverage
pytest tests/ -v --cov=app
# Run specific test file
pytest tests/test_scanner.py -v
```

### Frontend Tests
```bash
cd frontend
npm test
```

## 🔧 Configuration

### Environment Variables

```bash

ENVIRONMENT=development|production
REDIS_URL=redis://localhost:6379
API_HOST=0.0.0.0
API_PORT=8000


REACT_APP_API_URL=http://localhost:8000
```

### Scan Configuration

```python

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]

EXTENDED_PORTS = range(1, 1025) + [1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 9000]
```

## 🛠️ Development

### Project Structure

```
securescan-pro/
├── app/                   
│   ├── main.py            
│   ├── models.py          
│   ├── scanner.py         
│   └── report_generator.py 
├── frontend/              
│   ├── src/
│   │   ├── App.js         
│   │   ├── App.css        
│   │   └── index.js       
│   ├── package.json       
│   └── tailwind.config.js 
├── tests/                 
│   ├── test_main.py       
│   ├── test_scanner.py    
│   └── test_models.py     
├── .github/
│   └── workflows/
│       └── ci-cd.yml     
├── docker-compose.yml     
├── docker-compose.dev.yml 
├── Dockerfile            
├── requirements.txt     
└── README.md            
```

### Adding New Scan Components

1. **Define the component** in `models.py`:
```python
class ScanComponent(str, Enum):
    NEW_COMPONENT = "new_component"
```

2. **Implement scanner logic** in `scanner.py`:
```python
async def _new_component_scan(self, target: str) -> List[Dict[str, Any]]:
    
    pass
```

3. **Add to main scan method**:
```python
if ScanComponent.NEW_COMPONENT in components:
    results["new_component"] = await self._new_component_scan(target)
```

4. **Update frontend** in `App.js`:
```javascript
const componentLabels = {
    'new_component': 'New Component Name'
};
```

## 🔍 Security Details

### Port Scanning
- **TCP connect scan** 
- **Service detection** 
- **Banner grabbing ** - (service versions)
- **Async scanning for speed** 

### HTTP Headers
- **Checks for HSTS, CSP, X-Frame-Options, X-Content-Type, XSS-Protection, Referrer-Policy** 

### TLS/SSL Analysis
- **Detects SSL 3.0, TLS 1.0–1.3** 
- **Cipher suite strength check** 
- **Cert validation (chain + expiry)** 
- **Known SSL/TLS issues** 

### CVE Mapping
- **Service fingerprinting** 
- **Local CVE database** 
- **CVSS scoring** 
- **Suggestions for fixing** 

## 📊 Reports

### PDF
- **Summary + technical details** 
- **Risk levels** 
- **Recommendations** 

### JSON
- **Machine-readable** 
- **Full data included** 
- **Easy to parse** 

## 🚀 Deployment

### Docker Production Deployment

```bash

docker-compose up -d


docker-compose logs -f app


docker-compose up -d --scale app=3
```

### Kubernetes
```### Kubernetes (experimental)

I haven't deployed SecureScan Pro to Kubernetes yet, but this is the starting point I drafted for testing on a local cluster (minikube):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: securescan-pro
spec:
  replicas: 1
  selector:
    matchLabels:
      app: securescan-pro
  template:
    metadata:
      labels:
        app: securescan-pro
    spec:
      containers:
      - name: app
        image: maher92-collab/securescan-pro:latest
        ports:
        - containerPort: 8000

note: Still need to add Redis service and proper networking configuration

### CI/CD with GitHub Actions

- **AAutomated testing (frontend + backend)** 
- **Code linting and type checks** 
- **Security scanning with Trivy** 
- **Docker multi-platform builds** 
- **Auto deployment** 
- **Slack build notifications** 

## 🔧 Performance

### Backend
- **Async I/O** 
- **Connection pooling** 
- **Redis caching** 
- **Background tasks** 

### Frontend
- **Code splitting** - (lazy loading)
- **React.memo** 
- **Virtual scrolling** 
- **Progressive loading** 

## 🛡️ Security Built-In

### Input Validation
- **Input validation** - (domain/IP regex)
- **Rate limiting** 
- **Input sanitization** 
- **Proper CORS setup**
- **Non-root ports + Docker isolation**
- **HTTPS in prod**
- **JWT authentication**

## 📈 Monitoring & Logging

### Application Metrics
```python

from prometheus_client import Counter, Histogram
import logging


scan_counter = Counter('scans_total', 'Total number of scans')
scan_duration = Histogram('scan_duration_seconds', 'Scan duration')


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
```

### Health Checks
```bash

curl -f http://localhost:8000/ || exit 1


curl -f http://localhost:8000/health || exit 1
```

## 🤝 Contributing

1. **Fork repo**
2. **Create branch** (`git checkout -b feature/amazing-feature`)
3. **Commit changes** (`git commit -m 'Add amazing feature'`)
4. **git push** origin feature/amazing-feature`)

### Code Standards
- **Python**: PEP8 + type hints
- **JS**: ESLint rules
- **Tests**: 90%+ coverage
- **Docs updated when needed**

## 🙏 Thanks to

- **FastAPI** 
- **React** 
- **Tailwind CSS** 
- **Docker** 
- **GitHub Actions** 

## 📞 Support
- **Email**: maher.92@hotmail.com

---

**⚠️ Disclaimer**: Only use this tool on systems/networks you own or have permission to test.
