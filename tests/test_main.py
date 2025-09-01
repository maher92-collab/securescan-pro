# tests/test_main.py
import asyncio

import pytest
from httpx import AsyncClient

from app.main import app
from app.models import ScanComponent, ScanRequest, ScanType


@pytest.fixture
def client():
    return AsyncClient(app=app, base_url="http://test")

@pytest.mark.asyncio
async def test_root_endpoint(client):
    """Test the root endpoint"""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "SecureScan Pro API"
    assert data["version"] == "1.0.0"

@pytest.mark.asyncio
async def test_start_scan_valid_request(client):
    """Test starting a scan with valid request"""
    scan_data = {
        "target": "example.com",
        "scan_type": "quick",
        "components": ["tcp_port_scanning", "http_security_headers"]
    }
    
    response = await client.post("/scan", json=scan_data)
    assert response.status_code == 200
    
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "queued"
    assert data["message"] == "Scan queued successfully"

@pytest.mark.asyncio
async def test_start_scan_invalid_target(client):
    """Test starting a scan with invalid target"""
    scan_data = {
        "target": "",
        "scan_type": "quick",
        "components": ["tcp_port_scanning"]
    }
    
    response = await client.post("/scan", json=scan_data)
    assert response.status_code == 422  # Validation error

@pytest.mark.asyncio
async def test_get_scan_status_not_found(client):
    """Test getting status of non-existent job"""
    response = await client.get("/scan/nonexistent-job-id")
    assert response.status_code == 404
    data = response.json()
    assert data["detail"] == "Job not found"

@pytest.mark.asyncio 
async def test_get_report_not_found(client):
    """Test getting report of non-existent job"""
    response = await client.get("/report/nonexistent-job-id.json")
    assert response.status_code == 404
    data = response.json()
    assert data["detail"] == "Job not found"

import asyncio
from unittest.mock import AsyncMock, patch

# tests/test_scanner.py
import pytest

from app.models import ScanComponent, ScanType
from app.scanner import SecurityScanner


@pytest.fixture
def scanner():
    return SecurityScanner()

@pytest.mark.asyncio
async def test_port_scan_timeout():
    """Test port scanning with connection timeout"""
    scanner = SecurityScanner()
    
    # Test with unreachable target
    result = await scanner._scan_single_port("192.0.2.1", 80)  # RFC 5737 test address
    
    assert result["port"] == 80
    assert result["state"] == "closed"
    assert result["service"] == "HTTP"

def test_get_service_name():
    """Test service name lookup"""
    scanner = SecurityScanner()
    
    assert scanner._get_service_name(80) == "HTTP"
    assert scanner._get_service_name(443) == "HTTPS"
    assert scanner._get_service_name(22) == "SSH"
    assert scanner._get_service_name(99999) == "Unknown"

def test_analyze_security_header_missing():
    """Test security header analysis for missing header"""
    scanner = SecurityScanner()
    
    result = scanner._analyze_security_header("Strict-Transport-Security", None)
    
    assert result["header"] == "Strict-Transport-Security"
    assert result["value"] is None
    assert result["status"] == "missing"
    assert result["severity"] == "critical"

def test_analyze_security_header_present():
    """Test security header analysis for present header"""
    scanner = SecurityScanner()
    
    result = scanner._analyze_security_header("X-Frame-Options", "DENY")
    
    assert result["header"] == "X-Frame-Options"
    assert result["value"] == "DENY"
    assert result["status"] == "present"
    assert result["severity"] == "low"

@pytest.mark.asyncio
async def test_cve_mapping():
    """Test CVE mapping functionality"""
    scanner = SecurityScanner()
    
    port_results = [
        {"port": 22, "service": "SSH", "state": "open"},
        {"port": 80, "service": "HTTP", "state": "open"}
    ]
    
    vulnerabilities = await scanner._cve_mapping(port_results)
    
    assert len(vulnerabilities) >= 2  # Should find CVEs for SSH and HTTP
    assert any(vuln["affected_service"].startswith("SSH") for vuln in vulnerabilities)
    assert any(vuln["affected_service"].startswith("HTTP") for vuln in vulnerabilities)

def test_calculate_summary():
    """Test summary calculation"""
    scanner = SecurityScanner()
    
    results = {
        "security_headers": [
            {"status": "missing", "severity": "critical"},
            {"status": "weak", "severity": "high"},
            {"status": "present", "severity": "low"}
        ],
        "tls_analysis": [
            {"vulnerabilities": ["Deprecated protocol"]},
            {"vulnerabilities": []}
        ],
        "vulnerabilities": [
            {"severity": "critical"},
            {"severity": "medium"}
        ]
    }
    
    summary = scanner._calculate_summary(results)
    
    assert summary["total_issues"] == 5  # 2 headers + 1 TLS + 2 CVEs
    assert summary["critical"] == 2  # 1 header + 1 CVE
    assert summary["high"] == 1  # 1 header
    assert summary["medium"] == 2  # 1 TLS + 1 CVE

# tests/test_models.py
import pytest
from pydantic import ValidationError

from app.models import ScanComponent, ScanRequest, ScanType


def test_scan_request_valid():
    """Test valid scan request creation"""
    request = ScanRequest(
        target="example.com",
        scan_type=ScanType.QUICK,
        components=[ScanComponent.TCP_PORT_SCANNING]
    )
    
    assert request.target == "example.com"
    assert request.scan_type == ScanType.QUICK
    assert len(request.components) == 1

def test_scan_request_invalid_target():
    """Test scan request with invalid target"""
    with pytest.raises(ValidationError):
        ScanRequest(target="", scan_type=ScanType.QUICK)

def test_scan_request_cleanup_target():
    """Test target cleanup (remove protocol)"""
    request = ScanRequest(
        target="https://example.com",
        scan_type=ScanType.QUICK
    )
    
    assert request.target == "example.com"

def test_scan_request_ip_address():
    """Test scan request with IP address"""
    request = ScanRequest(
        target="192.168.1.1",
        scan_type=ScanType.DEEP
    )
    
    assert request.target == "192.168.1.1"

def test_scan_request_invalid_domain():
    """Test scan request with invalid domain format"""
    with pytest.raises(ValidationError):
        ScanRequest(target="invalid..domain", scan_type=ScanType.QUICK)