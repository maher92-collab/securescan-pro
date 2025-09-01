# app/models.py
import re
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, validator


class ScanType(str, Enum):
    QUICK = "quick"
    DEEP = "deep"

class ScanComponent(str, Enum):
    TCP_PORT_SCANNING = "tcp_port_scanning"
    HTTP_SECURITY_HEADERS = "http_security_headers"
    TLS_SSL_ANALYSIS = "tls_ssl_analysis"
    CVE_VULNERABILITY_MAPPING = "cve_vulnerability_mapping"

class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanRequest(BaseModel):
    target: str
    scan_type: ScanType = ScanType.QUICK
    components: List[ScanComponent] = [
        ScanComponent.TCP_PORT_SCANNING,
        ScanComponent.HTTP_SECURITY_HEADERS,
        ScanComponent.TLS_SSL_ANALYSIS
    ]
    
    @validator('target')
    def validate_target(cls, v):
        # Basic validation for domain/IP
        if not v or len(v.strip()) == 0:
            raise ValueError('Target cannot be empty')
        
        # Remove protocol if present
        target = v.strip()
        if target.startswith(('http://', 'https://')):
            target = target.split('://', 1)[1]
        
        # Basic domain/IP validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        if not (re.match(domain_pattern, target) or re.match(ip_pattern, target)):
            raise ValueError('Invalid domain or IP address format')
        
        return target

class ScanResponse(BaseModel):
    job_id: str
    status: ScanStatus
    message: str

class PortScanResult(BaseModel):
    port: int
    state: str
    service: str
    banner: Optional[str] = None

class SecurityHeader(BaseModel):
    header: str
    value: Optional[str]
    status: str  # "present", "missing", "weak"
    severity: str  # "low", "medium", "high", "critical"
    recommendation: str

class TLSResult(BaseModel):
    version: str
    supported: bool
    cipher_suites: List[str] = []
    vulnerabilities: List[str] = []

class CVEMatch(BaseModel):
    cve_id: str
    score: float
    severity: str
    description: str
    affected_service: str
    recommendation: str

class ScanResults(BaseModel):
    target: str
    scan_type: str
    timestamp: str
    duration_seconds: float
    summary: Dict[str, Any]
    port_scan: List[PortScanResult] = []
    security_headers: List[SecurityHeader] = []
    tls_analysis: List[TLSResult] = []
    vulnerabilities: List[CVEMatch] = []