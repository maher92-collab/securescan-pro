# app/scanner.py
import asyncio
import concurrent.futures
import json
import socket
import ssl
import subprocess
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import aiohttp

from .models import (CVEMatch, PortScanResult, ScanComponent, ScanResults,
                     ScanType, SecurityHeader, TLSResult)


class SecurityScanner:
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        self.extended_ports = list(range(1, 1025)) + [1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 9000]
        
    async def scan(
        self, 
        target: str, 
        scan_type: ScanType, 
        components: List[ScanComponent],
        progress_callback: Optional[Callable[[int], None]] = None
    ) -> Dict[str, Any]:
        """Main scan orchestrator"""
        start_time = time.time()
        results = {
            "target": target,
            "scan_type": scan_type,
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {"total_issues": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "port_scan": [],
            "security_headers": [],
            "tls_analysis": [],
            "vulnerabilities": []
        }
        
        total_components = len(components)
        completed_components = 0
        
        # TCP Port Scanning
        if ScanComponent.TCP_PORT_SCANNING in components:
            if progress_callback:
                progress_callback(20)
            results["port_scan"] = await self._port_scan(target, scan_type)
            completed_components += 1
            
        # HTTP Security Headers
        if ScanComponent.HTTP_SECURITY_HEADERS in components:
            if progress_callback:
                progress_callback(40)
            results["security_headers"] = await self._check_security_headers(target)
            completed_components += 1
            
        # TLS/SSL Analysis
        if ScanComponent.TLS_SSL_ANALYSIS in components:
            if progress_callback:
                progress_callback(60)
            results["tls_analysis"] = await self._tls_analysis(target)
            completed_components += 1
            
        # CVE Vulnerability Mapping
        if ScanComponent.CVE_VULNERABILITY_MAPPING in components:
            if progress_callback:
                progress_callback(80)
            results["vulnerabilities"] = await self._cve_mapping(results["port_scan"])
            completed_components += 1
        
        # Calculate summary
        results["summary"] = self._calculate_summary(results)
        results["duration_seconds"] = time.time() - start_time
        
        if progress_callback:
            progress_callback(100)
            
        return results
    
    async def _port_scan(self, target: str, scan_type: ScanType) -> List[Dict[str, Any]]:
        """TCP Port scanning with banner grabbing"""
        ports = self.common_ports if scan_type == ScanType.QUICK else self.extended_ports
        open_ports = []
        
        # Use asyncio for concurrent port scanning
        semaphore = asyncio.Semaphore(50)  # Limit concurrent connections
        
        async def scan_port(port):
            async with semaphore:
                return await self._scan_single_port(target, port)
        
        tasks = [scan_port(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, dict) and result.get("state") == "open":
                open_ports.append(result)
        
        return open_ports
    
    async def _scan_single_port(self, target: str, port: int) -> Dict[str, Any]:
        """Scan a single port with banner grabbing"""
        try:
            # Check if port is open
            future = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(future, timeout=3.0)
            
            # Get service name
            service = self._get_service_name(port)
            
            # Attempt banner grabbing
            banner = await self._grab_banner(reader, writer, port)
            
            writer.close()
            await writer.wait_closed()
            
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner
            }
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return {
                "port": port,
                "state": "closed",
                "service": self._get_service_name(port),
                "banner": None
            }
    
    async def _grab_banner(self, reader, writer, port: int) -> Optional[str]:
        """Grab service banner"""
        try:
            if port in [21, 22, 25, 110]:  # Services that send banner first
                banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                return banner.decode('utf-8', errors='ignore').strip()
            elif port in [80, 8080]:  # HTTP services
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
                await writer.drain()
                response = await asyncio.wait_for(reader.read(512), timeout=2.0)
                return response.decode('utf-8', errors='ignore').split('\n')[0].strip()
            else:
                # Try sending a generic probe
                writer.write(b"\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(512), timeout=1.0)
                return banner.decode('utf-8', errors='ignore').strip()
        except:
            return None
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8000: "HTTP-Alt",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "HTTP-Alt"
        }
        return services.get(port, "Unknown")
    
    async def _check_security_headers(self, target: str) -> List[Dict[str, Any]]:
        """Check HTTP security headers"""
        headers_to_check = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        
        security_headers = []
        
        for protocol in ["https", "http"]:
            try:
                url = f"{protocol}://{target}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10) as response:
                        for header_name in headers_to_check:
                            header_value = response.headers.get(header_name)
                            analysis = self._analyze_security_header(header_name, header_value)
                            security_headers.append(analysis)
                        break  # If HTTPS works, don't try HTTP
            except:
                continue
        
        return security_headers
    
    def _analyze_security_header(self, header_name: str, header_value: Optional[str]) -> Dict[str, Any]:
        """Analyze a security header"""
        if header_value is None:
            return {
                "header": header_name,
                "value": None,
                "status": "missing",
                "severity": self._get_header_severity(header_name, None),
                "recommendation": f"Implement {header_name} header for enhanced security"
            }
        
        # Basic analysis - in production, you'd want more sophisticated parsing
        status = "present"
        severity = "low"
        recommendation = "Header is present and appears configured"
        
        # Specific header analysis
        if header_name == "Strict-Transport-Security":
            if "max-age" not in header_value.lower():
                status = "weak"
                severity = "medium"
                recommendation = "HSTS header should include max-age directive"
        elif header_name == "Content-Security-Policy":
            if "unsafe-inline" in header_value or "unsafe-eval" in header_value:
                status = "weak"
                severity = "medium"
                recommendation = "CSP contains unsafe directives"
        
        return {
            "header": header_name,
            "value": header_value,
            "status": status,
            "severity": severity,
            "recommendation": recommendation
        }
    
    def _get_header_severity(self, header_name: str, header_value: Optional[str]) -> str:
        """Get severity for missing/weak headers"""
        critical_headers = ["Strict-Transport-Security"]
        high_headers = ["Content-Security-Policy", "X-Frame-Options"]
        medium_headers = ["X-Content-Type-Options", "X-XSS-Protection"]
        
        if header_name in critical_headers:
            return "critical"
        elif header_name in high_headers:
            return "high"
        elif header_name in medium_headers:
            return "medium"
        else:
            return "low"
    
    async def _tls_analysis(self, target: str) -> List[Dict[str, Any]]:
        """Analyze TLS/SSL configuration"""
        tls_results = []
        
        try:
            # Test different TLS versions
            tls_versions = [
                ("SSLv3", ssl.PROTOCOL_SSLv23),
                ("TLSv1.0", ssl.PROTOCOL_TLSv1),
                ("TLSv1.1", ssl.PROTOCOL_TLSv1_1),
                ("TLSv1.2", ssl.PROTOCOL_TLSv1_2),
                ("TLSv1.3", ssl.PROTOCOL_TLS)
            ]
            
            for version_name, protocol in tls_versions:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    # Create connection
                    sock = socket.create_connection((target, 443), timeout=5)
                    ssock = context.wrap_socket(sock, server_hostname=target)
                    
                    cipher_info = ssock.cipher()
                    tls_version = ssock.version()
                    
                    # Identify vulnerabilities based on version
                    vulnerabilities = []
                    if "SSLv" in version_name or "TLSv1.0" in version_name or "TLSv1.1" in version_name:
                        vulnerabilities.append("Deprecated protocol version")
                    
                    tls_results.append({
                        "version": tls_version or version_name,
                        "supported": True,
                        "cipher_suites": [cipher_info[0]] if cipher_info else [],
                        "vulnerabilities": vulnerabilities
                    })
                    
                    ssock.close()
                    
                except Exception:
                    tls_results.append({
                        "version": version_name,
                        "supported": False,
                        "cipher_suites": [],
                        "vulnerabilities": []
                    })
                    
        except Exception as e:
            return [{
                "version": "Unknown",
                "supported": False,
                "cipher_suites": [],
                "vulnerabilities": [f"TLS analysis failed: {str(e)}"]
            }]
        
        return tls_results
    
    async def _cve_mapping(self, port_scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map discovered services to known CVEs"""
        # This is a simplified implementation
        # In production, you'd use a real CVE database
        cve_database = {
            "SSH": [
                {
                    "cve_id": "CVE-2020-15778",
                    "score": 7.8,
                    "severity": "high",
                    "description": "OpenSSH privilege escalation vulnerability",
                    "recommendation": "Update to OpenSSH 8.3 or later"
                }
            ],
            "HTTP": [
                {
                    "cve_id": "CVE-2021-44228",
                    "score": 10.0,
                    "severity": "critical", 
                    "description": "Apache Log4j RCE vulnerability",
                    "recommendation": "Update Log4j to version 2.17.0 or later"
                }
            ],
            "FTP": [
                {
                    "cve_id": "CVE-2019-12815",
                    "score": 9.8,
                    "severity": "critical",
                    "description": "ProFTPD file copy vulnerability",
                    "recommendation": "Update ProFTPD to version 1.3.6b or later"
                }
            ]
        }
        
        vulnerabilities = []
        for port_result in port_scan_results:
            service = port_result.get("service")
            if service in cve_database:
                for cve in cve_database[service]:
                    vuln = cve.copy()
                    vuln["affected_service"] = f"{service} (port {port_result['port']})"
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _calculate_summary(self, results: Dict[str, Any]) -> Dict[str, int]:
        """Calculate summary statistics"""
        summary = {"total_issues": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        
        # Count security header issues
        for header in results.get("security_headers", []):
            if header["status"] in ["missing", "weak"]:
                severity = header["severity"]
                summary[severity] += 1
                summary["total_issues"] += 1
        
        # Count TLS issues
        for tls in results.get("tls_analysis", []):
            if tls["vulnerabilities"]:
                summary["medium"] += len(tls["vulnerabilities"])
                summary["total_issues"] += len(tls["vulnerabilities"])
        
        # Count CVE issues
        for vuln in results.get("vulnerabilities", []):
            severity = vuln["severity"]
            summary[severity] += 1
            summary["total_issues"] += 1
        
        return summary