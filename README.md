# SecureScan Pro

SecureScan Pro is a security scanning tool I’ve built for checking networks and web apps. It has a FastAPI backend and React frontend, with a clean modern UI (dark mode, glass style) that matches the design I had in mind.

👉 Live Demo: SecureScan Pro

Main interface
<img width="1911" height="912" alt="main interface" src="https://github.com/user-attachments/assets/3738ab22-a4eb-4b48-8fe8-57beb9e60e09" />

Scanning in Progress
<img width="1914" height="918" alt="scanning in progress" src="https://github.com/user-attachments/assets/be4f428d-a646-459a-a6a3-4be1acfac577" />

Security report
<img width="1907" height="913" alt="security report 1" src="https://github.com/user-attachments/assets/939443dd-aaf3-4d17-9b07-cc693ea41ea1" />

SecureScan Pro - Security Assessment Report

## 🔥 Main Features

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
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Frontend │    │  FastAPI Backend │    │   Redis Cache   │
│   (Port 3000)   │◄──►│   (Port 8000)   │◄──►│   (Port 6379)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       ▼                       │
         │              ┌─────────────────┐              │
         │              │  Security       │              │
         └──────────────┤  Scanner        │──────────────┘
                        │  Engine         │
                        └─────────────────┘
```

## 🚀 Quick Start

### Using Docker Compose 

```bash

git clone https://github.com/yourusername/securescan-pro.git
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

pytest tests/ -v --cov=app

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

## 🔍 Security Features

### Port Scanning
- **TCP Connect Scanning** - Full connection establishment
- **Service Detection** - Identify running services
- **Banner Grabbing** - Collect service version information
- **Concurrent Scanning** - Async I/O for performance

### HTTP Security Headers
- **Strict-Transport-Security** - HSTS implementation
- **Content-Security-Policy** - CSP configuration
- **X-Frame-Options** - Clickjacking protection
- **X-Content-Type-Options** - MIME type sniffing
- **X-XSS-Protection** - XSS filtering
- **Referrer-Policy** - Referrer information control

### TLS/SSL Analysis
- **Protocol Version Detection** - SSL 3.0, TLS 1.0-1.3
- **Cipher Suite Analysis** - Strong vs weak ciphers
- **Certificate Validation** - Chain and expiry checks
- **Vulnerability Detection** - Known SSL/TLS issues

### CVE Mapping
- **Service Fingerprinting** - Match services to versions
- **Vulnerability Database** - Local CVE mappings
- **CVSS Scoring** - Risk assessment
- **Remediation Guidance** - Actionable recommendations

## 📊 Report Features

### PDF Reports
- **Executive Summary** - High-level overview
- **Detailed Findings** - Technical details
- **Risk Assessment** - Severity-based categorization
- **Recommendations** - Actionable remediation steps

### JSON Reports
- **Machine Readable** - API integration friendly
- **Complete Data** - All scan results included
- **Structured Format** - Easy parsing and analysis

## 🚀 Deployment

### Docker Production Deployment

```bash

docker-compose up -d


docker-compose logs -f app


docker-compose up -d --scale app=3
```

### Kubernetes Deployment

```yaml
# k8s/deployment.yml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: securescan-pro
spec:
  replicas: 3
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
        image: yourusername/securescan-pro:latest
        ports:
        - containerPort: 8000
        env:
        - name: REDIS_URL
          value: "redis://redis-service:6379"
```

### GitHub Actions CI/CD

The project includes a comprehensive CI/CD pipeline:

- **Automated Testing** - Backend and frontend tests
- **Code Quality** - Linting and type checking
- **Security Scanning** - Trivy vulnerability scanner
- **Docker Build** - Multi-platform image builds
- **Deployment** - Automated production deployment
- **Notifications** - Slack integration for build status

## 🔧 Performance Optimization

### Backend Optimizations
- **Async I/O** - Non-blocking network operations
- **Connection Pooling** - Efficient resource utilization
- **Caching** - Redis for job state management
- **Background Tasks** - Non-blocking scan execution

### Frontend Optimizations
- **Code Splitting** - Lazy loading components
- **Memoization** - React.memo for performance
- **Virtual Scrolling** - Handle large result sets
- **Progressive Loading** - Stream scan results

## 🛡️ Security Considerations

### Input Validation
- **Domain/IP Validation** - Regex-based validation
- **Rate Limiting** - Prevent abuse
- **Sanitization** - Clean user inputs
- **CORS Configuration** - Proper cross-origin setup

### Network Security
- **Non-privileged Ports** - Run without root
- **Network Isolation** - Docker networking
- **TLS Encryption** - HTTPS in production
- **Authentication** - JWT token support

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

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit your changes** (`git commit -m 'Add amazing feature'`)
4. **Push to the branch** (`git push origin feature/amazing-feature`)
5. **Open a Pull Request**

### Code Standards
- **Python**: Follow PEP 8, use type hints
- **JavaScript**: ESLint configuration included
- **Tests**: Maintain >90% coverage
- **Documentation**: Update README for new features

## 🙏 Acknowledgments

- **FastAPI** - Modern Python web framework
- **React** - Frontend library
- **Tailwind CSS** - Utility-first CSS framework
- **Docker** - Containerization platform
- **GitHub Actions** - CI/CD automation

## 📞 Support
- **Email**: maher.92@hotmail.com

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Always ensure you have explicit permission before scanning any systems or networks that you do not own.
