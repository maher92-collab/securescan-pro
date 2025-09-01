// frontend/src/App.js
import React, { useState, useEffect } from 'react';
import { Shield, Target, Search, Download, CheckCircle, XCircle, AlertTriangle, Info } from 'lucide-react';
import './App.css';

const API_BASE = 'http://localhost:8000';

function App() {
  const [target, setTarget] = useState('google.com');
  const [scanType, setScanType] = useState('quick');
  const [components, setComponents] = useState([
    'tcp_port_scanning',
    'http_security_headers', 
    'tls_ssl_analysis'
  ]);
  const [isScanning, setIsScanning] = useState(false);
  const [currentJob, setCurrentJob] = useState(null);
  const [results, setResults] = useState(null);
  const [progress, setProgress] = useState(0);

  const componentLabels = {
    'tcp_port_scanning': 'TCP Port Scanning',
    'http_security_headers': 'HTTP Security Headers',
    'tls_ssl_analysis': 'TLS/SSL Analysis',
    'cve_vulnerability_mapping': 'CVE Vulnerability Mapping'
  };

  const handleStartScan = async () => {
    if (!target.trim()) return;
    
    setIsScanning(true);
    setProgress(0);
    setResults(null);
    
    try {
      const response = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target: target.trim(),
          scan_type: scanType,
          components: components
        })
      });
      
      const data = await response.json();
      setCurrentJob(data.job_id);
      
      // Poll for results
      pollScanResults(data.job_id);
    } catch (error) {
      console.error('Scan failed:', error);
      setIsScanning(false);
    }
  };

  const pollScanResults = async (jobId) => {
    const poll = async () => {
      try {
        const response = await fetch(`${API_BASE}/scan/${jobId}`);
        const data = await response.json();
        
        setProgress(data.progress || 0);
        
        if (data.status === 'completed') {
          setResults(data.results);
          setIsScanning(false);
          clearInterval(intervalId);
        } else if (data.status === 'failed') {
          console.error('Scan failed:', data.error);
          setIsScanning(false);
          clearInterval(intervalId);
        }
      } catch (error) {
        console.error('Polling error:', error);
        setIsScanning(false);
        clearInterval(intervalId);
      }
    };
    
    const intervalId = setInterval(poll, 1000);
    poll(); // Initial poll
  };

  const handleComponentToggle = (component) => {
    setComponents(prev => 
      prev.includes(component)
        ? prev.filter(c => c !== component)
        : [...prev, component]
    );
  };

  const downloadReport = async (format) => {
    if (!currentJob) return;
    
    try {
      const response = await fetch(`${API_BASE}/report/${currentJob}.${format}`);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan_report_${currentJob}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Download failed:', error);
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical': return <XCircle className="w-4 h-4 text-red-600" />;
      case 'high': return <AlertTriangle className="w-4 h-4 text-orange-600" />;
      case 'medium': return <AlertTriangle className="w-4 h-4 text-yellow-600" />;
      case 'low': return <Info className="w-4 h-4 text-blue-600" />;
      default: return <Info className="w-4 h-4 text-gray-600" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-blue-900">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-12 h-12 text-blue-400 mr-3" />
            <h1 className="text-4xl font-bold text-white">SecureScan Pro</h1>
          </div>
          <p className="text-gray-300 text-lg">
            Advanced security scanning platform for comprehensive network and web application assessments
          </p>
        </div>

        {/* Scanner Configuration */}
        <div className="bg-gray-800/50 backdrop-blur-sm rounded-2xl p-8 mb-8 border border-gray-700">
          <div className="flex items-center mb-6">
            <Target className="w-6 h-6 text-blue-400 mr-2" />
            <h2 className="text-2xl font-semibold text-white">Security Scanner Configuration</h2>
          </div>

          {/* Target Input */}
          <div className="mb-6">
            <label className="block text-gray-300 text-sm font-medium mb-2">
              Target Domain or IP Address
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="google.com"
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              disabled={isScanning}
            />
          </div>

          {/* Scan Type */}
          <div className="mb-6">
            <label className="block text-gray-300 text-sm font-medium mb-3">
              Scan Type
            </label>
            <div className="flex gap-4">
              <label className="flex items-center">
                <input
                  type="radio"
                  value="quick"
                  checked={scanType === 'quick'}
                  onChange={(e) => setScanType(e.target.value)}
                  className="mr-2 text-blue-600"
                  disabled={isScanning}
                />
                <span className="text-white">Quick Scan</span>
                <span className="text-gray-400 text-sm ml-2">(~2 minutes)</span>
              </label>
              <label className="flex items-center">
                <input
                  type="radio"
                  value="deep"
                  checked={scanType === 'deep'}
                  onChange={(e) => setScanType(e.target.value)}
                  className="mr-2 text-blue-600"
                  disabled={isScanning}
                />
                <span className="text-white">Deep Scan</span>
                <span className="text-gray-400 text-sm ml-2">(~15 minutes)</span>
              </label>
            </div>
          </div>

          {/* Scan Components */}
          <div className="mb-8">
            <label className="block text-gray-300 text-sm font-medium mb-3">
              Scan Components
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {Object.entries(componentLabels).map(([key, label]) => (
                <label key={key} className="flex items-center p-3 bg-gray-700/50 rounded-lg hover:bg-gray-700 transition-colors">
                  <input
                    type="checkbox"
                    checked={components.includes(key)}
                    onChange={() => handleComponentToggle(key)}
                    className="mr-3 text-blue-600 rounded"
                    disabled={isScanning}
                  />
                  <CheckCircle className="w-5 h-5 text-blue-400 mr-2" />
                  <span className="text-white">{label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Scan Button */}
          <button
            onClick={handleStartScan}
            disabled={isScanning || !target.trim() || components.length === 0}
            className="w-full bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 disabled:from-gray-600 disabled:to-gray-700 text-white font-semibold py-4 px-6 rounded-lg transition-all duration-200 flex items-center justify-center"
          >
            {isScanning ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                Scanning... ({progress}%)
              </>
            ) : (
              <>
                <Search className="w-5 h-5 mr-2" />
                Start Security Scan
              </>
            )}
          </button>

          {/* Progress Bar */}
          {isScanning && (
            <div className="mt-4">
              <div className="bg-gray-700 rounded-full h-2">
                <div 
                  className="bg-gradient-to-r from-blue-600 to-blue-400 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${progress}%` }}
                ></div>
              </div>
            </div>
          )}
        </div>

        {/* Results */}
        {results && (
          <div className="bg-gray-800/50 backdrop-blur-sm rounded-2xl p-8 border border-gray-700">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-semibold text-white">Scan Results</h2>
              <div className="flex gap-3">
                <button
                  onClick={() => downloadReport('json')}
                  className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg flex items-center transition-colors"
                >
                  <Download className="w-4 h-4 mr-2" />
                  JSON
                </button>
                <button
                  onClick={() => downloadReport('pdf')}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center transition-colors"
                >
                  <Download className="w-4 h-4 mr-2" />
                  PDF
                </button>
              </div>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
              <div className="bg-gray-700/50 p-4 rounded-lg">
                <div className="text-2xl font-bold text-white">{results.summary?.total_issues || 0}</div>
                <div className="text-gray-400 text-sm">Total Issues</div>
              </div>
              <div className="bg-red-900/30 p-4 rounded-lg border border-red-700/30">
                <div className="text-2xl font-bold text-red-400">{results.summary?.critical || 0}</div>
                <div className="text-gray-400 text-sm">Critical</div>
              </div>
              <div className="bg-orange-900/30 p-4 rounded-lg border border-orange-700/30">
                <div className="text-2xl font-bold text-orange-400">{results.summary?.high || 0}</div>
                <div className="text-gray-400 text-sm">High</div>
              </div>
              <div className="bg-yellow-900/30 p-4 rounded-lg border border-yellow-700/30">
                <div className="text-2xl font-bold text-yellow-400">{results.summary?.medium || 0}</div>
                <div className="text-gray-400 text-sm">Medium</div>
              </div>
              <div className="bg-blue-900/30 p-4 rounded-lg border border-blue-700/30">
                <div className="text-2xl font-bold text-blue-400">{results.summary?.low || 0}</div>
                <div className="text-gray-400 text-sm">Low</div>
              </div>
            </div>

            {/* Open Ports */}
            {results.port_scan && results.port_scan.length > 0 && (
              <div className="mb-8">
                <h3 className="text-xl font-semibold text-white mb-4">Open Ports</h3>
                <div className="bg-gray-700/30 rounded-lg overflow-hidden">
                  <table className="w-full">
                    <thead className="bg-gray-600">
                      <tr>
                        <th className="px-4 py-3 text-left text-white">Port</th>
                        <th className="px-4 py-3 text-left text-white">Service</th>
                        <th className="px-4 py-3 text-left text-white">Banner</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.port_scan.map((port, index) => (
                        <tr key={index} className="border-t border-gray-600">
                          <td className="px-4 py-3 text-white font-mono">{port.port}</td>
                          <td className="px-4 py-3 text-gray-300">{port.service}</td>
                          <td className="px-4 py-3 text-gray-400 text-sm">
                            {port.banner ? port.banner.substring(0, 50) + (port.banner.length > 50 ? '...' : '') : 'N/A'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Security Headers */}
            {results.security_headers && results.security_headers.length > 0 && (
              <div className="mb-8">
                <h3 className="text-xl font-semibold text-white mb-4">HTTP Security Headers</h3>
                <div className="space-y-3">
                  {results.security_headers.map((header, index) => (
                    <div key={index} className="bg-gray-700/30 p-4 rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center">
                          <span className="text-white font-medium">{header.header}</span>
                          <span className={`ml-3 px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(header.severity)}`}>
                            {header.severity.toUpperCase()}
                          </span>
                        </div>
                        {getSeverityIcon(header.severity)}
                      </div>
                      <div className="text-gray-300 text-sm mb-1">
                        Status: <span className={header.status === 'present' ? 'text-green-400' : 'text-red-400'}>
                          {header.status}
                        </span>
                      </div>
                      <div className="text-gray-400 text-sm">{header.recommendation}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Vulnerabilities */}
            {results.vulnerabilities && results.vulnerabilities.length > 0 && (
              <div className="mb-8">
                <h3 className="text-xl font-semibold text-white mb-4">Identified Vulnerabilities</h3>
                <div className="space-y-3">
                  {results.vulnerabilities.map((vuln, index) => (
                    <div key={index} className="bg-gray-700/30 p-4 rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center">
                          <span className="text-white font-medium">{vuln.cve_id}</span>
                          <span className="text-gray-400 ml-2">CVSS: {vuln.score}</span>
                          <span className={`ml-3 px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(vuln.severity)}`}>
                            {vuln.severity.toUpperCase()}
                          </span>
                        </div>
                        {getSeverityIcon(vuln.severity)}
                      </div>
                      <div className="text-gray-300 text-sm mb-1">
                        Affected: <span className="text-blue-400">{vuln.affected_service}</span>
                      </div>
                      <div className="text-gray-400 text-sm mb-2">{vuln.description}</div>
                      <div className="text-green-400 text-sm">{vuln.recommendation}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;