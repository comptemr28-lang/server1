// const express = require("express");
// const path = require("path");
// const fs = require("fs");
// const geoip = require("geoip-lite");
// const useragent = require("express-useragent");
// const crypto = require("crypto");
// const app = express();

// app.use(express.json({ limit: '10mb' }));
// app.use(useragent.express());

// // Enhanced data storage for DZBank
// class DZBankSecurityAnalytics {
//     constructor() {
//         this.sessions = new Map();
//         this.fingerprints = new Map();
//         this.anomalies = [];
//     }

//     createFingerprintHash(data) {
//         const str = JSON.stringify({
//             ip: data.ip,
//             ua: data.ua,
//             screen: data.screen,
//             plugins: data.plugins,
//             fonts: data.fonts
//         });
//         return crypto.createHash('sha256').update(str).digest('hex');
//     }

//     detectAnomaly(session) {
//         const anomalies = [];
        
//         // Safe header access with defaults
//         const headers = session.headers || {};
//         const ip = session.ip || '';
//         const userAgent = session.userAgent || '';
        
//         // Check for VPN/Proxy
//         if (headers['via'] || headers['x-forwarded-for']?.split(',').length > 2) {
//             anomalies.push('VPN/PROXY_DETECTED');
//         }
        
//         // Check for Tor
//         if (headers['from']?.includes('.onion') || 
//             ip.endsWith('.onion') ||
//             headers['host']?.includes('.onion')) {
//             anomalies.push('TOR_NETWORK_DETECTED');
//         }
        
//         // Check for headless browser
//         if (userAgent.includes('HeadlessChrome') || 
//             userAgent.includes('PhantomJS')) {
//             anomalies.push('HEADLESS_BROWSER');
//         }
        
//         // Check timezone mismatch
//         if (session.geo && session.browserTimezone && 
//             session.geo.timezone !== session.browserTimezone) {
//             anomalies.push('TIMEZONE_MISMATCH');
//         }
        
//         return anomalies;
//     }

//     logTransaction(uid, action, details) {
//         const log = {
//             timestamp: new Date().toISOString(),
//             uid,
//             action,
//             details,
//             sessionId: this.sessions.get(uid)?.sessionId
//         };
//         console.log(`DZBank Transaction: ${JSON.stringify(log)}`);
//         return log;
//     }
// }

// const dzAnalytics = new DZBankSecurityAnalytics();

// // Enhanced pixel tracking with security analytics
// app.get("/pixel.png", (req, res) => {
//     const uid = req.query.uid || 'anonymous';
//     const campaign = req.query.campaign || 'unknown';
//     const sessionId = req.query.session || crypto.randomBytes(16).toString('hex');
    
//     // Enhanced IP detection
//     const ip = req.headers['x-real-ip'] || 
//                req.headers['x-forwarded-for']?.split(',')[0].trim() || 
//                req.socket.remoteAddress ||
//                req.ip;
    
//     // Comprehensive header collection
//     const headers = {};
//     Object.keys(req.headers).forEach(key => {
//         if (key.startsWith('sec-') || key.startsWith('x-') || 
//             key.includes('client') || key.includes('user')) {
//             headers[key] = req.headers[key];
//         }
//     });
    
//     // Enhanced user agent parsing
//     const ua = req.headers['user-agent'] || 'unknown';
//     const parsedUA = req.useragent;
    
//     // Geolocation with ISP detection
//     const geo = geoip.lookup(ip) || {};
//     const isp = req.headers['x-isp'] || req.headers['x-organization'] || 'unknown';
    
//     // Connection information
//     const connection = {
//         protocol: req.protocol,
//         secure: req.secure,
//         host: req.headers['host'],
//         origin: req.headers['origin'] || req.headers['referer']
//     };
    
//     // Browser capabilities from headers
//     const capabilities = {
//         accepts: req.headers['accept'] || '',
//         languages: req.headers['accept-language'] || '',
//         encoding: req.headers['accept-encoding'] || '',
//         dnt: req.headers['dnt'] || '0',
//         saveData: req.headers['save-data'] || 'unknown'
//     };
    
//     // Security headers check
//     const securityHeaders = {
//         csp: req.headers['content-security-policy'] ? 'enabled' : 'disabled',
//         hsts: req.headers['strict-transport-security'] ? 'enabled' : 'disabled',
//         xFrame: req.headers['x-frame-options'] || 'not_set',
//         xss: req.headers['x-xss-protection'] || 'not_set'
//     };
    
//     const trackingData = {
//         type: 'PIXEL_TRACK',
//         timestamp: new Date().toISOString(),
//         uid,
//         sessionId,
//         campaign,
//         ip,
//         userAgent: ua,
//         headers: req.headers,
        
//         // Network Information
//         network: {
//             ip,
//             ipv: ip.includes(':') ? 'IPv6' : 'IPv4',
//             port: req.socket.remotePort,
//             localAddress: req.socket.localAddress,
//             localPort: req.socket.localPort,
//             proxy: req.headers['via'] || null,
//             xForwardedFor: req.headers['x-forwarded-for'] || null,
//             realIp: req.headers['x-real-ip'] || null
//         },
        
//         // Geolocation Data
//         geolocation: {
//             ...geo,
//             isp,
//             asn: req.headers['x-asn'] || null,
//             organization: req.headers['x-organization'] || null
//         },
        
//         // Device & Browser
//         device: {
//             userAgent: ua,
//             parsed: {
//                 browser: parsedUA.browser,
//                 version: parsedUA.version,
//                 os: parsedUA.os,
//                 platform: parsedUA.platform,
//                 source: ua,
//                 isMobile: parsedUA.isMobile,
//                 isTablet: parsedUA.isTablet,
//                 isDesktop: parsedUA.isDesktop,
//                 isBot: parsedUA.isBot,
//                 isAndroid: parsedUA.isAndroid,
//                 isiOS: parsedUA.isiOS,
//                 isWindows: parsedUA.isWindows,
//                 isMac: parsedUA.isMac,
//                 isLinux: parsedUA.isLinux
//             },
//             capabilities,
//             securityHeaders
//         },
        
//         // Connection
//         connection,
        
//         // Request Details
//         request: {
//             method: req.method,
//             url: req.url,
//             query: req.query,
//             headers: headers,
//             cookies: req.headers['cookie'] ? 'present' : 'absent',
//             referrer: req.headers['referer'] || 'direct',
//             referrerPolicy: req.headers['referrer-policy'] || 'not_set'
//         },
        
//         // Performance
//         performance: {
//             requestTime: Date.now(),
//             timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
//             loadTime: req.query.loadTime || 'unknown'
//         },
        
//         // DZBank Security Context
//         security: {
//             threatLevel: 'MONITORING',
//             sessionTrustScore: 85,
//             anomalies: [],
//             riskFactors: []
//         }
//     };
    
//     // Detect anomalies
//     trackingData.security.anomalies = dzAnalytics.detectAnomaly(trackingData);
    
//     // Store session
//     dzAnalytics.sessions.set(sessionId, trackingData);
    
//     // Log to console
//     console.log('🔐 DZBank Security Event:', JSON.stringify(trackingData, null, 2));
    
//     // Log to file
//     const logEntry = {
//         bank: 'DZBank',
//         department: 'Security Analytics',
//         ...trackingData
//     };
    
//     fs.appendFileSync('dzbank_security.log', JSON.stringify(logEntry) + '\n');
    
//     // Send 1x1 transparent PNG
//     res.set({
//         'Content-Type': 'image/png',
//         'Content-Length': '43',
//         'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
//         'Pragma': 'no-cache',
//         'Expires': '0',
//         'X-DZBank-Security': 'monitoring-enabled'
//     });
    
//     const pixel = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
//     res.send(pixel);
// });

// // Enhanced Fingerprint.js Script
// app.get("/fingerprint.js", (req, res) => {
//     const uid = req.query.uid || 'anonymous';
//     const sessionId = req.query.session || crypto.randomBytes(16).toString('hex');
    
//     const fingerprintScript = `
// // DZBank Security Fingerprint v2.0
// (function() {
//     'use strict';
    
//     const DZBank = {
//         version: '2.0',
//         sessionId: '${sessionId}',
//         uid: '${uid}',
//         timestamp: new Date().toISOString(),
        
//         collectHardwareInfo: function() {
//             return {
//                 // CPU Information
//                 cpu: {
//                     cores: navigator.hardwareConcurrency || 'unknown',
//                     architecture: navigator.cpuArchitecture || (() => {
//                         const ua = navigator.userAgent;
//                         if (ua.includes('x86_64') || ua.includes('x64')) return 'x64';
//                         if (ua.includes('x86') || ua.includes('i686')) return 'x86';
//                         if (ua.includes('arm64')) return 'arm64';
//                         if (ua.includes('arm')) return 'arm';
//                         return 'unknown';
//                     })(),
//                     memory: navigator.deviceMemory || 'unknown',
//                     maxTouchPoints: navigator.maxTouchPoints || 0
//                 },
                
//                 // GPU Information
//                 gpu: (function() {
//                     try {
//                         const canvas = document.createElement('canvas');
//                         const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
//                         if (gl) {
//                             const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
//                             if (debugInfo) {
//                                 return {
//                                     vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
//                                     renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL),
//                                     version: gl.getParameter(gl.VERSION),
//                                     shadingLanguage: gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
//                                 };
//                             }
//                         }
//                     } catch(e) {}
//                     return { vendor: 'unknown', renderer: 'unknown' };
//                 })(),
                
//                 // Screen Details
//                 screen: {
//                     width: screen.width,
//                     height: screen.height,
//                     availWidth: screen.availWidth,
//                     availHeight: screen.availHeight,
//                     colorDepth: screen.colorDepth,
//                     pixelDepth: screen.pixelDepth,
//                     orientation: screen.orientation ? screen.orientation.type : 'unknown',
//                     devicePixelRatio: window.devicePixelRatio || 1
//                 },
                
//                 // Browser Details
//                 browser: {
//                     userAgent: navigator.userAgent,
//                     platform: navigator.platform,
//                     language: navigator.language,
//                     cookieEnabled: navigator.cookieEnabled,
//                     doNotTrack: navigator.doNotTrack
//                 },
                
//                 // Connection Information
//                 connection: (function() {
//                     const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
//                     if (conn) {
//                         return {
//                             effectiveType: conn.effectiveType,
//                             rtt: conn.rtt,
//                             downlink: conn.downlink,
//                             saveData: conn.saveData
//                         };
//                     }
//                     return { effectiveType: 'unknown' };
//                 })(),
                
//                 // Canvas Fingerprinting
//                 canvasFingerprint: (function() {
//                     try {
//                         const canvas = document.createElement('canvas');
//                         const ctx = canvas.getContext('2d');
//                         canvas.width = 200;
//                         canvas.height = 50;
                        
//                         ctx.textBaseline = 'top';
//                         ctx.font = '14px Arial';
//                         ctx.fillText('DZBank Security', 10, 10);
                        
//                         return canvas.toDataURL().substring(0, 100);
//                     } catch(e) {
//                         return 'canvas_blocked';
//                     }
//                 })(),
                
//                 // Timezone & Locale
//                 locale: {
//                     timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
//                     locale: navigator.language
//                 },
                
//                 // Plugins
//                 plugins: (function() {
//                     const plugins = [];
//                     for (let i = 0; i < navigator.plugins.length; i++) {
//                         plugins.push({
//                             name: navigator.plugins[i].name,
//                             filename: navigator.plugins[i].filename
//                         });
//                     }
//                     return plugins;
//                 })(),
                
//                 // Fonts
//                 fonts: []
//             };
//         },
        
//         // Send data to DZBank Security
//         sendToDZBank: function(data) {
//             const payload = {
//                 dzbank_security: true,
//                 version: this.version,
//                 sessionId: this.sessionId,
//                 uid: this.uid,
//                 timestamp: this.timestamp,
//                 data: data
//             };
            
//             // Send via fetch
//             fetch('/collect-fingerprint', {
//                 method: 'POST',
//                 headers: {
//                     'Content-Type': 'application/json',
//                     'X-DZBank-Security': 'fingerprint-v2'
//                 },
//                 body: JSON.stringify(payload)
//             }).catch(err => console.error('Failed to send fingerprint:', err));
//         }
//     };
    
//     // Collect and send data
//     try {
//         const hardwareInfo = DZBank.collectHardwareInfo();
//         DZBank.sendToDZBank(hardwareInfo);
//         console.log('%cDZBank Security Active', 'color: #003399; font-weight: bold; font-size: 14px;');
//     } catch(e) {
//         console.error('DZBank Security Error:', e);
//     }
// })();
// `;
    
//     res.set({
//         'Content-Type': 'application/javascript',
//         'X-DZBank-Security': 'fingerprint-v2',
//         'Cache-Control': 'no-store, max-age=0'
//     });
    
//     res.send(fingerprintScript);
// });

// // Enhanced Collection Endpoint
// app.post("/collect-fingerprint", express.json(), (req, res) => {
//     try {
//         const fingerprintData = req.body;
        
//         // Validate incoming data
//         if (!fingerprintData || !fingerprintData.dzbank_security) {
//             return res.status(400).json({ error: 'Invalid DZBank security data' });
//         }
        
//         const sessionId = fingerprintData.sessionId || crypto.randomBytes(16).toString('hex');
        
//         // Get existing session with safe access
//         const session = dzAnalytics.sessions.get(sessionId) || {};
        
//         // Create comprehensive profile
//         const profile = {
//             type: 'COMPREHENSIVE_FINGERPRINT',
//             timestamp: new Date().toISOString(),
//             bank: 'DZBank',
//             department: 'Fraud Prevention',
//             riskLevel: 'ANALYZING',
            
//             session: sessionId,
//             uid: fingerprintData.uid,
            
//             // Combine pixel data with fingerprint
//             networkData: session.network || {},
//             geoData: session.geolocation || {},
            
//             // Hardware fingerprint
//             hardware: {
//                 cpu: fingerprintData.data?.cpu || {},
//                 gpu: fingerprintData.data?.gpu || {},
//                 memory: fingerprintData.data?.performance?.memory || {}
//             },
            
//             // Display & Graphics
//             display: {
//                 screen: fingerprintData.data?.screen || {},
//                 canvasHash: fingerprintData.data?.canvasFingerprint || 'unknown'
//             },
            
//             // Browser Details
//             browser: fingerprintData.data?.browser || {},
            
//             // Connection
//             connection: {
//                 browser: fingerprintData.data?.connection || {},
//                 server: session.connection || {}
//             },
            
//             // Locale & Time
//             locale: fingerprintData.data?.locale || {},
            
//             // Security Assessment
//             security: {
//                 fingerprintHash: crypto.randomBytes(16).toString('hex'),
//                 trustScore: calculateTrustScore(fingerprintData.data || {}),
//                 anomalies: session.security?.anomalies || [],
//                 recommendations: []
//             },
            
//             // DZBank Internal
//             internal: {
//                 processedBy: 'DZBank Security Engine v3.0',
//                 analysisTime: Date.now(),
//                 referenceId: `DZB-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
//                 compliance: {
//                     gdpr: 'PSEUDONYMIZED',
//                     pci_dss: 'LEVEL_1',
//                     banking_regulation: 'COMPLIANT'
//                 }
//             }
//         };
        
//         // Store fingerprint
//         dzAnalytics.fingerprints.set(profile.security.fingerprintHash, profile);
        
//         // Log transaction
//         dzAnalytics.logTransaction(fingerprintData.uid, 'FINGERPRINT_COLLECTED', {
//             hash: profile.security.fingerprintHash,
//             device: `${profile.browser.browser || 'unknown'} on ${profile.browser.platform || 'unknown'}`,
//             risk: profile.security.trustScore
//         });
        
//         console.log('🔐 DZBank Comprehensive Fingerprint:', JSON.stringify(profile, null, 2));
        
//         fs.appendFileSync('dzbank_fingerprints.log', JSON.stringify(profile) + '\n');
        
//         res.json({
//             status: 'success',
//             message: 'DZBank Security Data Collected',
//             reference: profile.internal.referenceId,
//             compliance: profile.internal.compliance
//         });
//     } catch (error) {
//         console.error('Error in collect-fingerprint:', error);
//         res.status(500).json({ 
//             error: 'Internal server error',
//             message: error.message 
//         });
//     }
// });

// // Helper functions
// function calculateTrustScore(data) {
//     let score = 100;
    
//     // Deduct for suspicious patterns
//     if (data.browser?.doNotTrack === '1') score -= 10;
//     if (data.connection?.effectiveType === '4g') score += 5;
//     if (data.connection?.saveData) score -= 5;
    
//     return Math.max(0, Math.min(100, score));
// }

// // Analytics Dashboard
// app.get("/dzbank-dashboard", (req, res) => {
//     res.send(`
//     <!DOCTYPE html>
//     <html>
//     <head>
//         <title>DZBank Security Analytics Dashboard</title>
//         <style>
//             body {
//                 font-family: 'Segoe UI', Arial, sans-serif;
//                 background: linear-gradient(135deg, #003399 0%, #0066cc 100%);
//                 color: white;
//                 margin: 0;
//                 padding: 20px;
//             }
//             .dashboard {
//                 max-width: 1200px;
//                 margin: 0 auto;
//                 background: rgba(255,255,255,0.1);
//                 backdrop-filter: blur(10px);
//                 border-radius: 20px;
//                 padding: 30px;
//                 box-shadow: 0 10px 40px rgba(0,0,0,0.3);
//             }
//             .header {
//                 display: flex;
//                 justify-content: space-between;
//                 align-items: center;
//                 margin-bottom: 30px;
//                 padding-bottom: 20px;
//                 border-bottom: 2px solid rgba(255,255,255,0.2);
//             }
//             .stats {
//                 display: grid;
//                 grid-template-columns: repeat(4, 1fr);
//                 gap: 20px;
//                 margin-bottom: 30px;
//             }
//             .stat-card {
//                 background: rgba(255,255,255,0.15);
//                 padding: 20px;
//                 border-radius: 10px;
//                 text-align: center;
//                 transition: transform 0.3s;
//             }
//             .stat-card:hover {
//                 transform: translateY(-5px);
//                 background: rgba(255,255,255,0.2);
//             }
//             .stat-number {
//                 font-size: 36px;
//                 font-weight: bold;
//                 color: #00ffcc;
//                 margin: 10px 0;
//             }
//             .sessions {
//                 background: rgba(255,255,255,0.1);
//                 padding: 20px;
//                 border-radius: 10px;
//                 margin-top: 30px;
//             }
//             table {
//                 width: 100%;
//                 border-collapse: collapse;
//                 margin-top: 20px;
//             }
//             th, td {
//                 padding: 12px;
//                 text-align: left;
//                 border-bottom: 1px solid rgba(255,255,255,0.1);
//             }
//             th {
//                 background: rgba(255,255,255,0.2);
//             }
//             .risk-high { color: #ff4444; }
//             .risk-medium { color: #ffaa00; }
//             .risk-low { color: #00ffaa; }
//         </style>
//     </head>
//     <body>
//         <div class="dashboard">
//             <div class="header">
//                 <div class="logo">
//                     <h1>🏦 DZBank Security Analytics</h1>
//                 </div>
//                 <div>v3.0 | Real-time Monitoring</div>
//             </div>
            
//             <div class="stats">
//                 <div class="stat-card">
//                     <div>Active Sessions</div>
//                     <div class="stat-number">${dzAnalytics.sessions.size}</div>
//                 </div>
//                 <div class="stat-card">
//                     <div>Fingerprints</div>
//                     <div class="stat-number">${dzAnalytics.fingerprints.size}</div>
//                 </div>
//                 <div class="stat-card">
//                     <div>Anomalies</div>
//                     <div class="stat-number">${dzAnalytics.anomalies.length}</div>
//                 </div>
//                 <div class="stat-card">
//                     <div>Trust Score</div>
//                     <div class="stat-number">85%</div>
//                 </div>
//             </div>
            
//             <div class="sessions">
//                 <h2>Recent Security Events</h2>
//                 <table>
//                     <thead>
//                         <tr>
//                             <th>Time</th>
//                             <th>Session ID</th>
//                             <th>Device</th>
//                             <th>Location</th>
//                             <th>Risk Level</th>
//                             <th>Anomalies</th>
//                         </tr>
//                     </thead>
//                     <tbody>
//                         ${Array.from(dzAnalytics.sessions.values()).slice(0, 10).map(session => `
//                         <tr>
//                             <td>${new Date(session.timestamp).toLocaleTimeString()}</td>
//                             <td>${session.sessionId?.substring(0, 8) || 'unknown'}...</td>
//                             <td>${session.device?.parsed?.browser || 'Unknown'} on ${session.device?.parsed?.os || 'Unknown'}</td>
//                             <td>${session.geolocation?.country || 'Unknown'}</td>
//                             <td class="risk-${session.security?.trustScore > 70 ? 'low' : session.security?.trustScore > 40 ? 'medium' : 'high'}">
//                                 ${session.security?.trustScore || 0}%
//                             </td>
//                             <td>${session.security?.anomalies?.join(', ') || 'None'}</td>
//                         </tr>
//                         `).join('')}
//                     </tbody>
//                 </table>
//             </div>
//         </div>
        
//         <script src="/fingerprint.js?uid=dashboard"></script>
//     </body>
//     </html>
//     `);
// });

// // Test endpoints
// app.get("/test-pixel", (req, res) => {
//     res.send(`
//     <html>
//     <head><title>DZBank Security Test</title></head>
//     <body>
//         <h1>DZBank Security Analytics Test</h1>
//         <p>This page includes the tracking pixel and fingerprint script.</p>
//         <img src="/pixel.png?uid=test_user_001&campaign=security_test" width="1" height="1">
//         <script src="/fingerprint.js?uid=test_user_001"></script>
//         <p>Check console for output and visit <a href="/dzbank-dashboard">Dashboard</a></p>
//     </body>
//     </html>
//     `);
// });

// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => {
//     console.log(`🏦 DZBank Security Analytics Server running on port ${PORT}`);
//     console.log(`📊 Dashboard: http://localhost:${PORT}/dzbank-dashboard`);
//     console.log(`🧪 Test Page: http://localhost:${PORT}/test-pixel`);

// });
// This is the previous working one 
// const express = require("express");
// const path = require("path");
// const fs = require("fs");
// const geoip = require("geoip-lite");
// const useragent = require("express-useragent");
// const crypto = require("crypto");
// const app = express();

// app.use(express.json({ limit: '10mb' }));
// app.use(useragent.express());

// // Enhanced data storage for DZBank
// class DZBankSecurityAnalytics {
//     constructor() {
//         this.sessions = new Map();
//         this.fingerprints = new Map();
//         this.anomalies = [];
//     }

//     createFingerprintHash(data) {
//         const str = JSON.stringify({
//             ip: data.ip,
//             ua: data.ua,
//             screen: data.screen,
//             plugins: data.plugins,
//             fonts: data.fonts
//         });
//         return crypto.createHash('sha256').update(str).digest('hex');
//     }

//     detectAnomaly(session) {
//         const anomalies = [];
        
//         // Safe header access with defaults
//         const headers = session.headers || {};
//         const ip = session.ip || '';
//         const userAgent = session.userAgent || '';
        
//         // Check for VPN/Proxy
//         if (headers['via'] || headers['x-forwarded-for']?.split(',').length > 2) {
//             anomalies.push('VPN/PROXY_DETECTED');
//         }
        
//         // Check for Tor
//         if (headers['from']?.includes('.onion') || 
//             ip.endsWith('.onion') ||
//             headers['host']?.includes('.onion')) {
//             anomalies.push('TOR_NETWORK_DETECTED');
//         }
        
//         // Check for headless browser
//         if (userAgent.includes('HeadlessChrome') || 
//             userAgent.includes('PhantomJS')) {
//             anomalies.push('HEADLESS_BROWSER');
//         }
        
//         // Check timezone mismatch
//         if (session.geo && session.browserTimezone && 
//             session.geo.timezone !== session.browserTimezone) {
//             anomalies.push('TIMEZONE_MISMATCH');
//         }
        
//         return anomalies;
//     }

//     logTransaction(uid, action, details) {
//         const log = {
//             timestamp: new Date().toISOString(),
//             uid,
//             action,
//             details,
//             sessionId: this.sessions.get(uid)?.sessionId
//         };
//         console.log(`DZBank Transaction: ${JSON.stringify(log)}`);
//         return log;
//     }
// }

// const dzAnalytics = new DZBankSecurityAnalytics();

// // Enhanced pixel tracking with security analytics
// app.get("/pixel.png", (req, res) => {
//     const uid = req.query.uid || 'anonymous';
//     const campaign = req.query.campaign || 'unknown';
//     const sessionId = req.query.session || crypto.randomBytes(16).toString('hex');
    
//     // Enhanced IP detection
//     const ip = req.headers['x-real-ip'] || 
//                req.headers['x-forwarded-for']?.split(',')[0].trim() || 
//                req.socket.remoteAddress ||
//                req.ip;
    
//     // Comprehensive header collection
//     const headers = {};
//     Object.keys(req.headers).forEach(key => {
//         if (key.startsWith('sec-') || key.startsWith('x-') || 
//             key.includes('client') || key.includes('user')) {
//             headers[key] = req.headers[key];
//         }
//     });
    
//     // Enhanced user agent parsing
//     const ua = req.headers['user-agent'] || 'unknown';
//     const parsedUA = req.useragent;
    
//     // Geolocation with ISP detection
//     const geo = geoip.lookup(ip) || {};
//     const isp = req.headers['x-isp'] || req.headers['x-organization'] || 'unknown';
    
//     // Connection information
//     const connection = {
//         protocol: req.protocol,
//         secure: req.secure,
//         host: req.headers['host'],
//         origin: req.headers['origin'] || req.headers['referer']
//     };
    
//     // Browser capabilities from headers
//     const capabilities = {
//         accepts: req.headers['accept'] || '',
//         languages: req.headers['accept-language'] || '',
//         encoding: req.headers['accept-encoding'] || '',
//         dnt: req.headers['dnt'] || '0',
//         saveData: req.headers['save-data'] || 'unknown'
//     };
    
//     // Security headers check
//     const securityHeaders = {
//         csp: req.headers['content-security-policy'] ? 'enabled' : 'disabled',
//         hsts: req.headers['strict-transport-security'] ? 'enabled' : 'disabled',
//         xFrame: req.headers['x-frame-options'] || 'not_set',
//         xss: req.headers['x-xss-protection'] || 'not_set'
//     };
    
//     const trackingData = {
//         type: 'PIXEL_TRACK',
//         timestamp: new Date().toISOString(),
//         uid,
//         sessionId,
//         campaign,
//         ip,
//         userAgent: ua,
//         headers: req.headers,
        
//         // Network Information
//         network: {
//             ip,
//             ipv: ip.includes(':') ? 'IPv6' : 'IPv4',
//             port: req.socket.remotePort,
//             localAddress: req.socket.localAddress,
//             localPort: req.socket.localPort,
//             proxy: req.headers['via'] || null,
//             xForwardedFor: req.headers['x-forwarded-for'] || null,
//             realIp: req.headers['x-real-ip'] || null
//         },
        
//         // Geolocation Data
//         geolocation: {
//             ...geo,
//             isp,
//             asn: req.headers['x-asn'] || null,
//             organization: req.headers['x-organization'] || null
//         },
        
//         // Device & Browser
//         device: {
//             userAgent: ua,
//             parsed: {
//                 browser: parsedUA.browser,
//                 version: parsedUA.version,
//                 os: parsedUA.os,
//                 platform: parsedUA.platform,
//                 source: ua,
//                 isMobile: parsedUA.isMobile,
//                 isTablet: parsedUA.isTablet,
//                 isDesktop: parsedUA.isDesktop,
//                 isBot: parsedUA.isBot,
//                 isAndroid: parsedUA.isAndroid,
//                 isiOS: parsedUA.isiOS,
//                 isWindows: parsedUA.isWindows,
//                 isMac: parsedUA.isMac,
//                 isLinux: parsedUA.isLinux
//             },
//             capabilities,
//             securityHeaders
//         },
        
//         // Connection
//         connection,
        
//         // Request Details
//         request: {
//             method: req.method,
//             url: req.url,
//             query: req.query,
//             headers: headers,
//             cookies: req.headers['cookie'] ? 'present' : 'absent',
//             referrer: req.headers['referer'] || 'direct',
//             referrerPolicy: req.headers['referrer-policy'] || 'not_set'
//         },
        
//         // Performance
//         performance: {
//             requestTime: Date.now(),
//             timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
//             loadTime: req.query.loadTime || 'unknown'
//         },
        
//         // DZBank Security Context
//         security: {
//             threatLevel: 'MONITORING',
//             sessionTrustScore: 85,
//             anomalies: [],
//             riskFactors: []
//         }
//     };
    
//     // Detect anomalies
//     trackingData.security.anomalies = dzAnalytics.detectAnomaly(trackingData);
    
//     // Store session
//     dzAnalytics.sessions.set(sessionId, trackingData);
    
//     // Log to console
//     console.log('🔐 DZBank Security Event:', JSON.stringify(trackingData, null, 2));
    
//     // Log to file
//     const logEntry = {
//         bank: 'DZBank',
//         department: 'Security Analytics',
//         ...trackingData
//     };
    
//     fs.appendFileSync('dzbank_security.log', JSON.stringify(logEntry) + '\n');
    
//     // Send 1x1 transparent PNG
//     res.set({
//         'Content-Type': 'image/png',
//         'Content-Length': '43',
//         'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
//         'Pragma': 'no-cache',
//         'Expires': '0',
//         'X-DZBank-Security': 'monitoring-enabled'
//     });
    
//     const pixel = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
//     res.send(pixel);
// });

// // Enhanced Fingerprint.js Script
// app.get("/fingerprint.js", (req, res) => {
//     const uid = req.query.uid || 'anonymous';
//     const sessionId = req.query.session || crypto.randomBytes(16).toString('hex');
    
//     const fingerprintScript = `
// // DZBank Security Fingerprint v2.0
// (function() {
//     'use strict';
    
//     const DZBank = {
//         version: '2.0',
//         sessionId: '${sessionId}',
//         uid: '${uid}',
//         timestamp: new Date().toISOString(),
        
//         collectHardwareInfo: function() {
//             return {
//                 // CPU Information
//                 cpu: {
//                     cores: navigator.hardwareConcurrency || 'unknown',
//                     architecture: navigator.cpuArchitecture || (() => {
//                         const ua = navigator.userAgent;
//                         if (ua.includes('x86_64') || ua.includes('x64')) return 'x64';
//                         if (ua.includes('x86') || ua.includes('i686')) return 'x86';
//                         if (ua.includes('arm64')) return 'arm64';
//                         if (ua.includes('arm')) return 'arm';
//                         return 'unknown';
//                     })(),
//                     memory: navigator.deviceMemory || 'unknown',
//                     maxTouchPoints: navigator.maxTouchPoints || 0
//                 },
                
//                 // GPU Information
//                 gpu: (function() {
//                     try {
//                         const canvas = document.createElement('canvas');
//                         const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
//                         if (gl) {
//                             const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
//                             if (debugInfo) {
//                                 return {
//                                     vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
//                                     renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL),
//                                     version: gl.getParameter(gl.VERSION),
//                                     shadingLanguage: gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
//                                 };
//                             }
//                         }
//                     } catch(e) {}
//                     return { vendor: 'unknown', renderer: 'unknown' };
//                 })(),
                
//                 // Screen Details
//                 screen: {
//                     width: screen.width,
//                     height: screen.height,
//                     availWidth: screen.availWidth,
//                     availHeight: screen.availHeight,
//                     colorDepth: screen.colorDepth,
//                     pixelDepth: screen.pixelDepth,
//                     orientation: screen.orientation ? screen.orientation.type : 'unknown',
//                     devicePixelRatio: window.devicePixelRatio || 1
//                 },
                
//                 // Browser Details
//                 browser: {
//                     userAgent: navigator.userAgent,
//                     platform: navigator.platform,
//                     language: navigator.language,
//                     cookieEnabled: navigator.cookieEnabled,
//                     doNotTrack: navigator.doNotTrack
//                 },
                
//                 // Connection Information
//                 connection: (function() {
//                     const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
//                     if (conn) {
//                         return {
//                             effectiveType: conn.effectiveType,
//                             rtt: conn.rtt,
//                             downlink: conn.downlink,
//                             saveData: conn.saveData
//                         };
//                     }
//                     return { effectiveType: 'unknown' };
//                 })(),
                
//                 // Canvas Fingerprinting
//                 canvasFingerprint: (function() {
//                     try {
//                         const canvas = document.createElement('canvas');
//                         const ctx = canvas.getContext('2d');
//                         canvas.width = 200;
//                         canvas.height = 50;
                        
//                         ctx.textBaseline = 'top';
//                         ctx.font = '14px Arial';
//                         ctx.fillText('DZBank Security', 10, 10);
                        
//                         return canvas.toDataURL().substring(0, 100);
//                     } catch(e) {
//                         return 'canvas_blocked';
//                     }
//                 })(),
                
//                 // Timezone & Locale
//                 locale: {
//                     timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
//                     locale: navigator.language
//                 },
                
//                 // Plugins
//                 plugins: (function() {
//                     const plugins = [];
//                     for (let i = 0; i < navigator.plugins.length; i++) {
//                         plugins.push({
//                             name: navigator.plugins[i].name,
//                             filename: navigator.plugins[i].filename
//                         });
//                     }
//                     return plugins;
//                 })(),
                
//                 // Fonts
//                 fonts: []
//             };
//         },
        
//         // Send data to DZBank Security
//         sendToDZBank: function(data) {
//             const payload = {
//                 dzbank_security: true,
//                 version: this.version,
//                 sessionId: this.sessionId,
//                 uid: this.uid,
//                 timestamp: this.timestamp,
//                 data: data
//             };
            
//             // Send via fetch
//             fetch('/collect-fingerprint', {
//                 method: 'POST',
//                 headers: {
//                     'Content-Type': 'application/json',
//                     'X-DZBank-Security': 'fingerprint-v2'
//                 },
//                 body: JSON.stringify(payload)
//             }).catch(err => console.error('Failed to send fingerprint:', err));
//         }
//     };
    
//     // Collect and send data
//     try {
//         const hardwareInfo = DZBank.collectHardwareInfo();
//         DZBank.sendToDZBank(hardwareInfo);
//         console.log('%cDZBank Security Active', 'color: #003399; font-weight: bold; font-size: 14px;');
//     } catch(e) {
//         console.error('DZBank Security Error:', e);
//     }
// })();
// `;
    
//     res.set({
//         'Content-Type': 'application/javascript',
//         'X-DZBank-Security': 'fingerprint-v2',
//         'Cache-Control': 'no-store, max-age=0'
//     });
    
//     res.send(fingerprintScript);
// });

// // Enhanced Collection Endpoint
// app.post("/collect-fingerprint", express.json(), (req, res) => {
//     try {
//         const fingerprintData = req.body;
        
//         // Validate incoming data
//         if (!fingerprintData || !fingerprintData.dzbank_security) {
//             return res.status(400).json({ error: 'Invalid DZBank security data' });
//         }
        
//         const sessionId = fingerprintData.sessionId || crypto.randomBytes(16).toString('hex');
        
//         // Get existing session with safe access
//         const session = dzAnalytics.sessions.get(sessionId) || {};
        
//         // Create comprehensive profile
//         const profile = {
//             type: 'COMPREHENSIVE_FINGERPRINT',
//             timestamp: new Date().toISOString(),
//             bank: 'DZBank',
//             department: 'Fraud Prevention',
//             riskLevel: 'ANALYZING',
            
//             session: sessionId,
//             uid: fingerprintData.uid,
            
//             // Combine pixel data with fingerprint
//             networkData: session.network || {},
//             geoData: session.geolocation || {},
            
//             // Hardware fingerprint
//             hardware: {
//                 cpu: fingerprintData.data?.cpu || {},
//                 gpu: fingerprintData.data?.gpu || {},
//                 memory: fingerprintData.data?.performance?.memory || {}
//             },
            
//             // Display & Graphics
//             display: {
//                 screen: fingerprintData.data?.screen || {},
//                 canvasHash: fingerprintData.data?.canvasFingerprint || 'unknown'
//             },
            
//             // Browser Details
//             browser: fingerprintData.data?.browser || {},
            
//             // Connection
//             connection: {
//                 browser: fingerprintData.data?.connection || {},
//                 server: session.connection || {}
//             },
            
//             // Locale & Time
//             locale: fingerprintData.data?.locale || {},
            
//             // Security Assessment
//             security: {
//                 fingerprintHash: crypto.randomBytes(16).toString('hex'),
//                 trustScore: calculateTrustScore(fingerprintData.data || {}),
//                 anomalies: session.security?.anomalies || [],
//                 recommendations: []
//             },
            
//             // DZBank Internal
//             internal: {
//                 processedBy: 'DZBank Security Engine v3.0',
//                 analysisTime: Date.now(),
//                 referenceId: `DZB-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
//                 compliance: {
//                     gdpr: 'PSEUDONYMIZED',
//                     pci_dss: 'LEVEL_1',
//                     banking_regulation: 'COMPLIANT'
//                 }
//             }
//         };
        
//         // Store fingerprint
//         dzAnalytics.fingerprints.set(profile.security.fingerprintHash, profile);
        
//         // Log transaction
//         dzAnalytics.logTransaction(fingerprintData.uid, 'FINGERPRINT_COLLECTED', {
//             hash: profile.security.fingerprintHash,
//             device: `${profile.browser.browser || 'unknown'} on ${profile.browser.platform || 'unknown'}`,
//             risk: profile.security.trustScore
//         });
        
//         console.log('🔐 DZBank Comprehensive Fingerprint:', JSON.stringify(profile, null, 2));
        
//         fs.appendFileSync('dzbank_fingerprints.log', JSON.stringify(profile) + '\n');
        
//         res.json({
//             status: 'success',
//             message: 'DZBank Security Data Collected',
//             reference: profile.internal.referenceId,
//             compliance: profile.internal.compliance
//         });
//     } catch (error) {
//         console.error('Error in collect-fingerprint:', error);
//         res.status(500).json({ 
//             error: 'Internal server error',
//             message: error.message 
//         });
//     }
// });

// // Helper functions
// function calculateTrustScore(data) {
//     let score = 100;
    
//     // Deduct for suspicious patterns
//     if (data.browser?.doNotTrack === '1') score -= 10;
//     if (data.connection?.effectiveType === '4g') score += 5;
//     if (data.connection?.saveData) score -= 5;
    
//     return Math.max(0, Math.min(100, score));
// }

// // Analytics Dashboard
// // Add this middleware for basic authentication
// app.use('/dzbank-dashboard', (req, res, next) => {
//     const authHeader = req.headers.authorization;
    
//     if (!authHeader) {
//         res.setHeader('WWW-Authenticate', 'Basic realm="DZBank Security Dashboard"');
//         return res.status(401).send('Authentication required');
//     }
    
//     const auth = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
//     const username = auth[0];
//     const password = auth[1];
    
//     if (username === 'admin' && password === 'salmen1234') {
//         next();
//     } else {
//         res.setHeader('WWW-Authenticate', 'Basic realm="DZBank Security Dashboard"');
//         return res.status(401).send('Invalid credentials');
//     }
// });

// // Enhanced Dashboard with Full Data Display
// app.get("/dzbank-dashboard", (req, res) => {
//     const allSessions = Array.from(dzAnalytics.sessions.values());
//     const allFingerprints = Array.from(dzAnalytics.fingerprints.values());
    
//     res.send(`
//     <!DOCTYPE html>
//     <html>
//     <head>
//         <title>DZBank Security Analytics Dashboard</title>
//         <style>
//             * {
//                 margin: 0;
//                 padding: 0;
//                 box-sizing: border-box;
//             }
            
//             body {
//                 font-family: 'Segoe UI', Arial, sans-serif;
//                 background: linear-gradient(135deg, #003399 0%, #0066cc 100%);
//                 color: white;
//                 padding: 20px;
//             }
            
//             .dashboard {
//                 max-width: 1400px;
//                 margin: 0 auto;
//             }
            
//             .header {
//                 background: rgba(255,255,255,0.1);
//                 backdrop-filter: blur(10px);
//                 border-radius: 20px;
//                 padding: 30px;
//                 margin-bottom: 20px;
//                 box-shadow: 0 10px 40px rgba(0,0,0,0.3);
//                 display: flex;
//                 justify-content: space-between;
//                 align-items: center;
//             }
            
//             .logo h1 {
//                 font-size: 32px;
//                 margin-bottom: 5px;
//             }
            
//             .stats {
//                 display: grid;
//                 grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
//                 gap: 20px;
//                 margin-bottom: 20px;
//             }
            
//             .stat-card {
//                 background: rgba(255,255,255,0.15);
//                 backdrop-filter: blur(10px);
//                 padding: 25px;
//                 border-radius: 15px;
//                 text-align: center;
//                 transition: transform 0.3s, background 0.3s;
//                 box-shadow: 0 5px 20px rgba(0,0,0,0.2);
//             }
            
//             .stat-card:hover {
//                 transform: translateY(-5px);
//                 background: rgba(255,255,255,0.2);
//             }
            
//             .stat-label {
//                 font-size: 14px;
//                 opacity: 0.9;
//                 margin-bottom: 10px;
//             }
            
//             .stat-number {
//                 font-size: 42px;
//                 font-weight: bold;
//                 color: #00ffcc;
//             }
            
//             .section {
//                 background: rgba(255,255,255,0.1);
//                 backdrop-filter: blur(10px);
//                 padding: 25px;
//                 border-radius: 15px;
//                 margin-bottom: 20px;
//                 box-shadow: 0 5px 20px rgba(0,0,0,0.2);
//             }
            
//             .section h2 {
//                 margin-bottom: 20px;
//                 font-size: 24px;
//                 display: flex;
//                 align-items: center;
//                 gap: 10px;
//             }
            
//             .data-container {
//                 max-height: 600px;
//                 overflow-y: auto;
//                 background: rgba(0,0,0,0.3);
//                 border-radius: 10px;
//                 padding: 20px;
//             }
            
//             .data-item {
//                 background: rgba(255,255,255,0.05);
//                 border-left: 4px solid #00ffcc;
//                 padding: 20px;
//                 margin-bottom: 15px;
//                 border-radius: 8px;
//                 transition: background 0.3s;
//             }
            
//             .data-item:hover {
//                 background: rgba(255,255,255,0.1);
//             }
            
//             .data-header {
//                 display: flex;
//                 justify-content: space-between;
//                 align-items: center;
//                 margin-bottom: 15px;
//                 padding-bottom: 10px;
//                 border-bottom: 1px solid rgba(255,255,255,0.2);
//             }
            
//             .session-id {
//                 font-weight: bold;
//                 color: #00ffcc;
//                 font-size: 16px;
//             }
            
//             .timestamp {
//                 color: #ffaa00;
//                 font-size: 14px;
//             }
            
//             .data-grid {
//                 display: grid;
//                 grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
//                 gap: 15px;
//                 margin-bottom: 15px;
//             }
            
//             .data-field {
//                 background: rgba(0,0,0,0.2);
//                 padding: 12px;
//                 border-radius: 6px;
//             }
            
//             .field-label {
//                 font-size: 12px;
//                 opacity: 0.7;
//                 margin-bottom: 5px;
//                 text-transform: uppercase;
//             }
            
//             .field-value {
//                 font-size: 14px;
//                 word-break: break-all;
//             }
            
//             .json-display {
//                 background: rgba(0,0,0,0.4);
//                 padding: 15px;
//                 border-radius: 8px;
//                 font-family: 'Courier New', monospace;
//                 font-size: 12px;
//                 overflow-x: auto;
//                 white-space: pre-wrap;
//                 word-wrap: break-word;
//             }
            
//             .risk-badge {
//                 display: inline-block;
//                 padding: 5px 15px;
//                 border-radius: 20px;
//                 font-size: 12px;
//                 font-weight: bold;
//             }
            
//             .risk-high { background: #ff4444; }
//             .risk-medium { background: #ffaa00; }
//             .risk-low { background: #00ffaa; color: #000; }
            
//             .anomaly-badge {
//                 display: inline-block;
//                 background: #ff4444;
//                 padding: 4px 10px;
//                 border-radius: 12px;
//                 font-size: 11px;
//                 margin-right: 5px;
//                 margin-bottom: 5px;
//             }
            
//             .toggle-btn {
//                 background: rgba(255,255,255,0.2);
//                 border: none;
//                 color: white;
//                 padding: 8px 20px;
//                 border-radius: 6px;
//                 cursor: pointer;
//                 font-size: 12px;
//                 transition: background 0.3s;
//             }
            
//             .toggle-btn:hover {
//                 background: rgba(255,255,255,0.3);
//             }
            
//             .tabs {
//                 display: flex;
//                 gap: 10px;
//                 margin-bottom: 20px;
//             }
            
//             .tab {
//                 background: rgba(255,255,255,0.1);
//                 padding: 12px 25px;
//                 border-radius: 8px;
//                 cursor: pointer;
//                 transition: all 0.3s;
//                 border: 2px solid transparent;
//             }
            
//             .tab:hover {
//                 background: rgba(255,255,255,0.2);
//             }
            
//             .tab.active {
//                 background: rgba(0,255,204,0.2);
//                 border-color: #00ffcc;
//             }
            
//             .tab-content {
//                 display: none;
//             }
            
//             .tab-content.active {
//                 display: block;
//             }
            
//             ::-webkit-scrollbar {
//                 width: 10px;
//             }
            
//             ::-webkit-scrollbar-track {
//                 background: rgba(0,0,0,0.2);
//                 border-radius: 5px;
//             }
            
//             ::-webkit-scrollbar-thumb {
//                 background: rgba(0,255,204,0.5);
//                 border-radius: 5px;
//             }
            
//             ::-webkit-scrollbar-thumb:hover {
//                 background: rgba(0,255,204,0.7);
//             }
//         </style>
//     </head>
//     <body>
//         <div class="dashboard">
//             <div class="header">
//                 <div class="logo">
//                     <h1>🏦 DZBank Security Analytics</h1>
//                     <div style="font-size: 14px; opacity: 0.8;">Real-time Fraud Prevention & Monitoring</div>
//                 </div>
//                 <div>
//                     <div style="font-size: 12px; opacity: 0.7;">Logged in as: admin</div>
//                     <div>v3.0 | ${new Date().toLocaleString()}</div>
//                 </div>
//             </div>
            
//             <div class="stats">
//                 <div class="stat-card">
//                     <div class="stat-label">Active Sessions</div>
//                     <div class="stat-number">${dzAnalytics.sessions.size}</div>
//                 </div>
//                 <div class="stat-card">
//                     <div class="stat-label">Fingerprints Collected</div>
//                     <div class="stat-number">${dzAnalytics.fingerprints.size}</div>
//                 </div>
//                 <div class="stat-card">
//                     <div class="stat-label">Total Anomalies</div>
//                     <div class="stat-number">${allSessions.reduce((sum, s) => sum + (s.security?.anomalies?.length || 0), 0)}</div>
//                 </div>
//                 <div class="stat-card">
//                     <div class="stat-label">Average Trust Score</div>
//                     <div class="stat-number">${allSessions.length > 0 ? Math.round(allSessions.reduce((sum, s) => sum + (s.security?.trustScore || 0), 0) / allSessions.length) : 0}%</div>
//                 </div>
//             </div>
            
//             <div class="section">
//                 <div class="tabs">
//                     <div class="tab active" onclick="switchTab('sessions')">
//                         📊 Sessions (${allSessions.length})
//                     </div>
//                     <div class="tab" onclick="switchTab('fingerprints')">
//                         🔍 Fingerprints (${allFingerprints.length})
//                     </div>
//                 </div>
                
//                 <div id="sessions-tab" class="tab-content active">
//                     <h2>🔐 All Session Data</h2>
//                     <div class="data-container">
//                         ${allSessions.length === 0 ? '<p style="text-align: center; opacity: 0.7;">No sessions recorded yet</p>' : ''}
//                         ${allSessions.map((session, index) => `
//                             <div class="data-item">
//                                 <div class="data-header">
//                                     <div>
//                                         <div class="session-id">Session #${index + 1}: ${session.sessionId || 'Unknown'}</div>
//                                         <div style="font-size: 12px; opacity: 0.8; margin-top: 5px;">
//                                             User: ${session.uid || 'Anonymous'} | Campaign: ${session.campaign || 'N/A'}
//                                         </div>
//                                     </div>
//                                     <div style="text-align: right;">
//                                         <div class="timestamp">${new Date(session.timestamp).toLocaleString()}</div>
//                                         <div style="margin-top: 5px;">
//                                             <span class="risk-badge risk-${session.security?.trustScore > 70 ? 'low' : session.security?.trustScore > 40 ? 'medium' : 'high'}">
//                                                 Trust: ${session.security?.trustScore || 0}%
//                                             </span>
//                                         </div>
//                                     </div>
//                                 </div>
                                
//                                 <div class="data-grid">
//                                     <div class="data-field">
//                                         <div class="field-label">IP Address</div>
//                                         <div class="field-value">${session.ip || 'Unknown'} (${session.network?.ipv || 'Unknown'})</div>
//                                     </div>
                                    
//                                     <div class="data-field">
//                                         <div class="field-label">Location</div>
//                                         <div class="field-value">
//                                             ${session.geolocation?.country || 'Unknown'} 
//                                             ${session.geolocation?.city ? `- ${session.geolocation.city}` : ''}
//                                             <br><small>Timezone: ${session.geolocation?.timezone || 'Unknown'}</small>
//                                         </div>
//                                     </div>
                                    
//                                     <div class="data-field">
//                                         <div class="field-label">Device</div>
//                                         <div class="field-value">
//                                             ${session.device?.parsed?.browser || 'Unknown'} ${session.device?.parsed?.version || ''}
//                                             <br><small>${session.device?.parsed?.os || 'Unknown OS'} - ${session.device?.parsed?.platform || 'Unknown'}</small>
//                                         </div>
//                                     </div>
                                    
//                                     <div class="data-field">
//                                         <div class="field-label">Connection</div>
//                                         <div class="field-value">
//                                             ${session.connection?.protocol || 'Unknown'}://${session.connection?.host || 'Unknown'}
//                                             <br><small>Secure: ${session.connection?.secure ? 'Yes' : 'No'}</small>
//                                         </div>
//                                     </div>
//                                 </div>
                                
//                                 ${session.security?.anomalies?.length > 0 ? `
//                                     <div style="margin-top: 15px;">
//                                         <div class="field-label">⚠️ Security Anomalies</div>
//                                         <div style="margin-top: 8px;">
//                                             ${session.security.anomalies.map(a => `<span class="anomaly-badge">${a}</span>`).join('')}
//                                         </div>
//                                     </div>
//                                 ` : ''}
                                
//                                 <div style="margin-top: 15px;">
//                                     <button class="toggle-btn" onclick="toggleJson('session-${index}')">
//                                         📋 View Complete JSON Data
//                                     </button>
//                                     <div id="session-${index}" class="json-display" style="display: none; margin-top: 10px;">
// ${JSON.stringify(session, null, 2)}
//                                     </div>
//                                 </div>
//                             </div>
//                         `).join('')}
//                     </div>
//                 </div>
                
//                 <div id="fingerprints-tab" class="tab-content">
//                     <h2>🔍 All Fingerprint Data</h2>
//                     <div class="data-container">
//                         ${allFingerprints.length === 0 ? '<p style="text-align: center; opacity: 0.7;">No fingerprints collected yet</p>' : ''}
//                         ${allFingerprints.map((fp, index) => `
//                             <div class="data-item">
//                                 <div class="data-header">
//                                     <div>
//                                         <div class="session-id">Fingerprint #${index + 1}</div>
//                                         <div style="font-size: 12px; opacity: 0.8; margin-top: 5px;">
//                                             Reference: ${fp.internal?.referenceId || 'Unknown'}
//                                         </div>
//                                     </div>
//                                     <div style="text-align: right;">
//                                         <div class="timestamp">${new Date(fp.timestamp).toLocaleString()}</div>
//                                         <div style="margin-top: 5px;">
//                                             <span class="risk-badge risk-${fp.security?.trustScore > 70 ? 'low' : fp.security?.trustScore > 40 ? 'medium' : 'high'}">
//                                                 Trust: ${fp.security?.trustScore || 0}%
//                                             </span>
//                                         </div>
//                                     </div>
//                                 </div>
                                
//                                 <div class="data-grid">
//                                     <div class="data-field">
//                                         <div class="field-label">Hardware</div>
//                                         <div class="field-value">
//                                             CPU: ${fp.hardware?.cpu?.cores || 'Unknown'} cores (${fp.hardware?.cpu?.architecture || 'Unknown'})
//                                             <br>Memory: ${fp.hardware?.cpu?.memory || 'Unknown'} GB
//                                         </div>
//                                     </div>
                                    
//                                     <div class="data-field">
//                                         <div class="field-label">GPU</div>
//                                         <div class="field-value">
//                                             ${fp.hardware?.gpu?.vendor || 'Unknown'}
//                                             <br><small>${fp.hardware?.gpu?.renderer ? fp.hardware.gpu.renderer.substring(0, 50) : 'Unknown'}...</small>
//                                         </div>
//                                     </div>
                                    
//                                     <div class="data-field">
//                                         <div class="field-label">Screen</div>
//                                         <div class="field-value">
//                                             ${fp.display?.screen?.width || 0}x${fp.display?.screen?.height || 0}
//                                             <br><small>Color Depth: ${fp.display?.screen?.colorDepth || 'Unknown'}-bit | DPR: ${fp.display?.screen?.devicePixelRatio || 1}</small>
//                                         </div>
//                                     </div>
                                    
//                                     <div class="data-field">
//                                         <div class="field-label">Browser</div>
//                                         <div class="field-value">
//                                             ${fp.browser?.platform || 'Unknown'}
//                                             <br><small>Language: ${fp.browser?.language || 'Unknown'} | Cookies: ${fp.browser?.cookieEnabled ? 'Enabled' : 'Disabled'}</small>
//                                         </div>
//                                     </div>
                                    
//                                     <div class="data-field">
//                                         <div class="field-label">Connection</div>
//                                         <div class="field-value">
//                                             ${fp.connection?.browser?.effectiveType || 'Unknown'}
//                                             <br><small>RTT: ${fp.connection?.browser?.rtt || 'Unknown'}ms | Downlink: ${fp.connection?.browser?.downlink || 'Unknown'} Mbps</small>
//                                         </div>
//                                     </div>
                                    
//                                     <div class="data-field">
//                                         <div class="field-label">Locale</div>
//                                         <div class="field-value">
//                                             Timezone: ${fp.locale?.timezone || 'Unknown'}
//                                             <br><small>Language: ${fp.locale?.locale || 'Unknown'}</small>
//                                         </div>
//                                     </div>
//                                 </div>
                                
//                                 <div style="margin-top: 15px;">
//                                     <button class="toggle-btn" onclick="toggleJson('fingerprint-${index}')">
//                                         📋 View Complete JSON Data
//                                     </button>
//                                     <div id="fingerprint-${index}" class="json-display" style="display: none; margin-top: 10px;">
// ${JSON.stringify(fp, null, 2)}
//                                     </div>
//                                 </div>
//                             </div>
//                         `).join('')}
//                     </div>
//                 </div>
//             </div>
//         </div>
        
//         <script>
//             function toggleJson(id) {
//                 const element = document.getElementById(id);
//                 if (element.style.display === 'none') {
//                     element.style.display = 'block';
//                 } else {
//                     element.style.display = 'none';
//                 }
//             }
            
//             function switchTab(tabName) {
//                 // Hide all tabs
//                 document.querySelectorAll('.tab-content').forEach(tab => {
//                     tab.classList.remove('active');
//                 });
//                 document.querySelectorAll('.tab').forEach(tab => {
//                     tab.classList.remove('active');
//                 });
                
//                 // Show selected tab
//                 document.getElementById(tabName + '-tab').classList.add('active');
//                 event.target.classList.add('active');
//             }
            
//             // Auto-refresh every 30 seconds
//             setTimeout(() => {
//                 location.reload();
//             }, 30000);
//         </script>
//     </body>
//     </html>
//     `);
// });

// // Test endpoints
// app.get("/test-pixel", (req, res) => {
//     res.send(`
//     <html>
//     <head><title>DZBank Security Test</title></head>
//     <body>
//         <h1>DZBank Security Analytics Test</h1>
//         <p>This page includes the tracking pixel and fingerprint script.</p>
//         <img src="/pixel.png?uid=test_user_001&campaign=security_test" width="1" height="1">
//         <script src="/fingerprint.js?uid=test_user_001"></script>
//         <p>Check console for output and visit <a href="/dzbank-dashboard">Dashboard</a></p>
//     </body>
//     </html>
//     `);
// });

// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => {
//     console.log(`🏦 DZBank Security Analytics Server running on port ${PORT}`);
//     console.log(`📊 Dashboard: http://localhost:${PORT}/dzbank-dashboard`);
//     console.log(`🧪 Test Page: http://localhost:${PORT}/test-pixel`);
// });


const express = require("express");
const path = require("path");
const fs = require("fs");
const geoip = require("geoip-lite");
const useragent = require("express-useragent");
const crypto = require("crypto");
const app = express();
const Database = require('better-sqlite3');
const db = new Database('dzbank_security.db');
const publicIp = require('public-ip');
const https = require('https');
// Initialize database tables
db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE,
        uid TEXT,
        campaign TEXT,
        ip TEXT,
        timestamp TEXT,
        data TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS fingerprints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint_hash TEXT UNIQUE,
        session_id TEXT,
        uid TEXT,
        timestamp TEXT,
        data TEXT,
        trust_score INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_session_id ON sessions(session_id);
    CREATE INDEX IF NOT EXISTS idx_fingerprint_hash ON fingerprints(fingerprint_hash);
    CREATE INDEX IF NOT EXISTS idx_uid ON sessions(uid);
`);

app.use(express.json({ limit: '10mb' }));
app.use(useragent.express());

// Enhanced data storage for DZBank
class DZBankSecurityAnalytics {
    constructor() {
        this.sessions = new Map();
        this.fingerprints = new Map();
        this.anomalies = [];
        this.loadFromDatabase(); // Add this line

    }

    loadFromDatabase() {
    // Load sessions
    const sessions = db.prepare('SELECT * FROM sessions ORDER BY created_at DESC LIMIT 1000').all();
    sessions.forEach(row => {
        this.sessions.set(row.session_id, JSON.parse(row.data));
    });

    // Load fingerprints
    const fingerprints = db.prepare('SELECT * FROM fingerprints ORDER BY created_at DESC LIMIT 1000').all();
    fingerprints.forEach(row => {
        this.fingerprints.set(row.fingerprint_hash, JSON.parse(row.data));
    });
    
    console.log(`📂 Loaded ${sessions.length} sessions and ${fingerprints.length} fingerprints from database`);
}

saveSession(sessionId, data) {
    const stmt = db.prepare(`
        INSERT OR REPLACE INTO sessions (session_id, uid, campaign, ip, timestamp, data)
        VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    stmt.run(
        sessionId,
        data.uid || 'anonymous',
        data.campaign || 'unknown',
        data.ip || 'unknown',
        data.timestamp,
        JSON.stringify(data)
    );
}

saveFingerprint(hash, data) {
    const stmt = db.prepare(`
        INSERT OR REPLACE INTO fingerprints (fingerprint_hash, session_id, uid, timestamp, data, trust_score)
        VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    stmt.run(
        hash,
        data.session || 'unknown',
        data.uid || 'unknown',
        data.timestamp,
        JSON.stringify(data),
        data.security?.trustScore || 0
    );
}

    createFingerprintHash(data) {
        const str = JSON.stringify({
            ip: data.ip,
            ua: data.ua,
            screen: data.screen,
            plugins: data.plugins,
            fonts: data.fonts
        });
        return crypto.createHash('sha256').update(str).digest('hex');
    }

    detectAnomaly(session) {
        const anomalies = [];
        
        // Safe header access with defaults
        const headers = session.headers || {};
        const ip = session.ip || '';
        const userAgent = session.userAgent || '';
        
        // Check for VPN/Proxy
        if (headers['via'] || headers['x-forwarded-for']?.split(',').length > 2) {
            anomalies.push('VPN/PROXY_DETECTED');
        }
        
        // Check for Tor
        if (headers['from']?.includes('.onion') || 
            ip.endsWith('.onion') ||
            headers['host']?.includes('.onion')) {
            anomalies.push('TOR_NETWORK_DETECTED');
        }
        
        // Check for headless browser
        if (userAgent.includes('HeadlessChrome') || 
            userAgent.includes('PhantomJS')) {
            anomalies.push('HEADLESS_BROWSER');
        }
        
        // Check timezone mismatch
        if (session.geo && session.browserTimezone && 
            session.geo.timezone !== session.browserTimezone) {
            anomalies.push('TIMEZONE_MISMATCH');
        }
        
        return anomalies;
    }

    logTransaction(uid, action, details) {
        const log = {
            timestamp: new Date().toISOString(),
            uid,
            action,
            details,
            sessionId: this.sessions.get(uid)?.sessionId
        };
        console.log(`DZBank Transaction: ${JSON.stringify(log)}`);
        return log;
    }
}

const dzAnalytics = new DZBankSecurityAnalytics();

app.get("/health", (req, res) => {
    res.status(200).send("OK");
});


// Enhanced pixel tracking with security analytics
app.get("/pixel.png", (req, res) => {
    const uid = req.query.uid || 'anonymous';
    const campaign = req.query.campaign || 'unknown';
    const sessionId = req.query.session || crypto.randomBytes(16).toString('hex');
    
    // Enhanced IP detection
    const ip = req.headers['x-real-ip'] || 
               req.headers['x-forwarded-for']?.split(',')[0].trim() || 
               req.socket.remoteAddress ||
               req.ip;
    
    // Comprehensive header collection
    const headers = {};
    Object.keys(req.headers).forEach(key => {
        if (key.startsWith('sec-') || key.startsWith('x-') || 
            key.includes('client') || key.includes('user')) {
            headers[key] = req.headers[key];
        }
    });
    
    // Enhanced user agent parsing
    const ua = req.headers['user-agent'] || 'unknown';
    const parsedUA = req.useragent;
    
    // Geolocation with ISP detection
    const geo = geoip.lookup(ip) || {};
    const isp = req.headers['x-isp'] || req.headers['x-organization'] || 'unknown';
    
    // Connection information
    const connection = {
        protocol: req.protocol,
        secure: req.secure,
        host: req.headers['host'],
        origin: req.headers['origin'] || req.headers['referer']
    };
    
    // Browser capabilities from headers
    const capabilities = {
        accepts: req.headers['accept'] || '',
        languages: req.headers['accept-language'] || '',
        encoding: req.headers['accept-encoding'] || '',
        dnt: req.headers['dnt'] || '0',
        saveData: req.headers['save-data'] || 'unknown'
    };
    
    // Security headers check
    const securityHeaders = {
        csp: req.headers['content-security-policy'] ? 'enabled' : 'disabled',
        hsts: req.headers['strict-transport-security'] ? 'enabled' : 'disabled',
        xFrame: req.headers['x-frame-options'] || 'not_set',
        xss: req.headers['x-xss-protection'] || 'not_set'
    };
    
    const trackingData = {
        type: 'PIXEL_TRACK',
        timestamp: new Date().toISOString(),
        uid,
        sessionId,
        campaign,
        ip,
        userAgent: ua,
        headers: req.headers,
        
        // Network Information
        network: {
            ip,
            ipv: ip.includes(':') ? 'IPv6' : 'IPv4',
            port: req.socket.remotePort,
            localAddress: req.socket.localAddress,
            localPort: req.socket.localPort,
            proxy: req.headers['via'] || null,
            xForwardedFor: req.headers['x-forwarded-for'] || null,
            realIp: req.headers['x-real-ip'] || null
        },
        
        // Geolocation Data
        geolocation: {
            ...geo,
            isp,
            asn: req.headers['x-asn'] || null,
            organization: req.headers['x-organization'] || null
        },
        
        // Device & Browser
        device: {
            userAgent: ua,
            parsed: {
                browser: parsedUA.browser,
                version: parsedUA.version,
                os: parsedUA.os,
                platform: parsedUA.platform,
                source: ua,
                isMobile: parsedUA.isMobile,
                isTablet: parsedUA.isTablet,
                isDesktop: parsedUA.isDesktop,
                isBot: parsedUA.isBot,
                isAndroid: parsedUA.isAndroid,
                isiOS: parsedUA.isiOS,
                isWindows: parsedUA.isWindows,
                isMac: parsedUA.isMac,
                isLinux: parsedUA.isLinux
            },
            capabilities,
            securityHeaders
        },
        
        // Connection
        connection,
        
        // Request Details
        request: {
            method: req.method,
            url: req.url,
            query: req.query,
            headers: headers,
            cookies: req.headers['cookie'] ? 'present' : 'absent',
            referrer: req.headers['referer'] || 'direct',
            referrerPolicy: req.headers['referrer-policy'] || 'not_set'
        },
        
        // Performance
        performance: {
            requestTime: Date.now(),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            loadTime: req.query.loadTime || 'unknown'
        },
        
        // DZBank Security Context
        security: {
            threatLevel: 'MONITORING',
            sessionTrustScore: 85,
            anomalies: [],
            riskFactors: []
        }
    };
    
    // Detect anomalies
    trackingData.security.anomalies = dzAnalytics.detectAnomaly(trackingData);
    
    // Store session
    dzAnalytics.sessions.set(sessionId, trackingData);
    dzAnalytics.saveSession(sessionId, trackingData); // Add this line

    
    // Log to console
    console.log('🔐 DZBank Security Event:', JSON.stringify(trackingData, null, 2));
    
    // Log to file
    const logEntry = {
        bank: 'DZBank',
        department: 'Security Analytics',
        ...trackingData
    };
    
    fs.appendFileSync('dzbank_security.log', JSON.stringify(logEntry) + '\n');
    
    // Send 1x1 transparent PNG
    res.set({
        'Content-Type': 'image/png',
        'Content-Length': '43',
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        'Pragma': 'no-cache',
        'Expires': '0',
        'X-DZBank-Security': 'monitoring-enabled'
    });
    
    const pixel = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
    res.send(pixel);
});

// Enhanced Fingerprint.js Script
app.get("/fingerprint.js", (req, res) => {
    const uid = req.query.uid || 'anonymous';
    const sessionId = req.query.session || crypto.randomBytes(16).toString('hex');
    
    const fingerprintScript = `
// DZBank Security Fingerprint v2.0
(function() {
    'use strict';
    
    const DZBank = {
        version: '2.0',
        sessionId: '${sessionId}',
        uid: '${uid}',
        timestamp: new Date().toISOString(),
        
        collectHardwareInfo: function() {
            return {
                // CPU Information
                cpu: {
                    cores: navigator.hardwareConcurrency || 'unknown',
                    architecture: navigator.cpuArchitecture || (() => {
                        const ua = navigator.userAgent;
                        if (ua.includes('x86_64') || ua.includes('x64')) return 'x64';
                        if (ua.includes('x86') || ua.includes('i686')) return 'x86';
                        if (ua.includes('arm64')) return 'arm64';
                        if (ua.includes('arm')) return 'arm';
                        return 'unknown';
                    })(),
                    memory: navigator.deviceMemory || 'unknown',
                    maxTouchPoints: navigator.maxTouchPoints || 0
                },
                
                // GPU Information
                gpu: (function() {
                    try {
                        const canvas = document.createElement('canvas');
                        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                        if (gl) {
                            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                            if (debugInfo) {
                                return {
                                    vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
                                    renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL),
                                    version: gl.getParameter(gl.VERSION),
                                    shadingLanguage: gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
                                };
                            }
                        }
                    } catch(e) {}
                    return { vendor: 'unknown', renderer: 'unknown' };
                })(),
                
                // Screen Details
                screen: {
                    width: screen.width,
                    height: screen.height,
                    availWidth: screen.availWidth,
                    availHeight: screen.availHeight,
                    colorDepth: screen.colorDepth,
                    pixelDepth: screen.pixelDepth,
                    orientation: screen.orientation ? screen.orientation.type : 'unknown',
                    devicePixelRatio: window.devicePixelRatio || 1
                },
                
                // Browser Details
                browser: {
                    userAgent: navigator.userAgent,
                    platform: navigator.platform,
                    language: navigator.language,
                    cookieEnabled: navigator.cookieEnabled,
                    doNotTrack: navigator.doNotTrack
                },
                
                // Connection Information
                connection: (function() {
                    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
                    if (conn) {
                        return {
                            effectiveType: conn.effectiveType,
                            rtt: conn.rtt,
                            downlink: conn.downlink,
                            saveData: conn.saveData
                        };
                    }
                    return { effectiveType: 'unknown' };
                })(),
                
                // Canvas Fingerprinting
                canvasFingerprint: (function() {
                    try {
                        const canvas = document.createElement('canvas');
                        const ctx = canvas.getContext('2d');
                        canvas.width = 200;
                        canvas.height = 50;
                        
                        ctx.textBaseline = 'top';
                        ctx.font = '14px Arial';
                        ctx.fillText('DZBank Security', 10, 10);
                        
                        return canvas.toDataURL().substring(0, 100);
                    } catch(e) {
                        return 'canvas_blocked';
                    }
                })(),
                
                // Timezone & Locale
                locale: {
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    locale: navigator.language
                },
                
                // Plugins
                plugins: (function() {
                    const plugins = [];
                    for (let i = 0; i < navigator.plugins.length; i++) {
                        plugins.push({
                            name: navigator.plugins[i].name,
                            filename: navigator.plugins[i].filename
                        });
                    }
                    return plugins;
                })(),
                
                // Fonts
                fonts: []
            };
        },
        
        // Send data to DZBank Security
        sendToDZBank: function(data) {
            const payload = {
                dzbank_security: true,
                version: this.version,
                sessionId: this.sessionId,
                uid: this.uid,
                timestamp: this.timestamp,
                data: data
            };
            
            // Send via fetch
            fetch('/collect-fingerprint', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-DZBank-Security': 'fingerprint-v2'
                },
                body: JSON.stringify(payload)
            }).catch(err => console.error('Failed to send fingerprint:', err));
        }
    };
    
    // Collect and send data
    try {
        const hardwareInfo = DZBank.collectHardwareInfo();
        DZBank.sendToDZBank(hardwareInfo);
        console.log('%cDZBank Security Active', 'color: #003399; font-weight: bold; font-size: 14px;');
    } catch(e) {
        console.error('DZBank Security Error:', e);
    }
})();
`;
    
    res.set({
        'Content-Type': 'application/javascript',
        'X-DZBank-Security': 'fingerprint-v2',
        'Cache-Control': 'no-store, max-age=0'
    });
    
    res.send(fingerprintScript);
});

// WebRTC IP Detection Script
app.get("/webrtc-ip.js", (req, res) => {
    const webrtcScript = `
// WebRTC Private IP Detection
(function() {
    'use strict';
    
    function getLocalIPs(callback) {
        const ips = [];
        const RTCPeerConnection = window.RTCPeerConnection || 
                                 window.mozRTCPeerConnection || 
                                 window.webkitRTCPeerConnection;
        
        if (!RTCPeerConnection) {
            callback([]);
            return;
        }
        
        const pc = new RTCPeerConnection({
            iceServers: [{urls: 'stun:stun.l.google.com:19302'}]
        });
        
        pc.createDataChannel('');
        
        pc.onicecandidate = (ice) => {
            if (!ice || !ice.candidate || !ice.candidate.candidate) {
                callback(ips);
                return;
            }
            
            const parts = ice.candidate.candidate.split(' ');
            const ip = parts[4];
            const type = parts[7];
            
            if (ip && ips.indexOf(ip) === -1) {
                ips.push({
                    ip: ip,
                    type: type
                });
            }
        };
        
        pc.createOffer()
            .then(offer => pc.setLocalDescription(offer))
            .catch(err => console.error('WebRTC Error:', err));
        
        setTimeout(() => {
            pc.close();
            callback(ips);
        }, 2000);
    }
    
    getLocalIPs((ips) => {
        fetch('/collect-webrtc-ip', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-DZBank-Security': 'webrtc-ip'
            },
            body: JSON.stringify({
                privateIPs: ips,
                timestamp: new Date().toISOString(),
                uid: new URLSearchParams(window.location.search).get('uid') || 'anonymous'
            })
        }).catch(err => console.error('Failed to send WebRTC IPs:', err));
    });
})();
`;
    
    res.set({
        'Content-Type': 'application/javascript',
        'X-DZBank-Security': 'webrtc-ip',
        'Cache-Control': 'no-store, max-age=0'
    });
    
    res.send(webrtcScript);
});

// Collect WebRTC Private IPs
app.post("/collect-webrtc-ip", express.json(), (req, res) => {
    try {
        const data = req.body;
        const sessionId = req.query.session || 'unknown';
        
        console.log('🌐 WebRTC Private IPs:', JSON.stringify(data, null, 2));
        
        // Update existing session with private IPs
        const session = dzAnalytics.sessions.get(sessionId);
        if (session) {
            session.privateIPs = data.privateIPs;
            dzAnalytics.sessions.set(sessionId, session);
            
            // Update in database if you added it
            if (dzAnalytics.saveSession) {
                dzAnalytics.saveSession(sessionId, session);
            }
        }
        
        fs.appendFileSync('dzbank_webrtc.log', JSON.stringify(data) + '\n');
        
        res.json({ status: 'success', message: 'WebRTC IPs collected' });
    } catch (error) {
        console.error('Error collecting WebRTC IPs:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Enhanced Collection Endpoint
app.post("/collect-fingerprint", express.json(), (req, res) => {
    try {
        const fingerprintData = req.body;
        
        // Validate incoming data
        if (!fingerprintData || !fingerprintData.dzbank_security) {
            return res.status(400).json({ error: 'Invalid DZBank security data' });
        }
        
        const sessionId = fingerprintData.sessionId || crypto.randomBytes(16).toString('hex');
        
        // Get existing session with safe access
        const session = dzAnalytics.sessions.get(sessionId) || {};
        
        // Create comprehensive profile
        const profile = {
            type: 'COMPREHENSIVE_FINGERPRINT',
            timestamp: new Date().toISOString(),
            bank: 'DZBank',
            department: 'Fraud Prevention',
            riskLevel: 'ANALYZING',
            
            session: sessionId,
            uid: fingerprintData.uid,
            
            // Combine pixel data with fingerprint
            networkData: session.network || {},
            geoData: session.geolocation || {},
            
            // Hardware fingerprint
            hardware: {
                cpu: fingerprintData.data?.cpu || {},
                gpu: fingerprintData.data?.gpu || {},
                memory: fingerprintData.data?.performance?.memory || {}
            },
            
            // Display & Graphics
            display: {
                screen: fingerprintData.data?.screen || {},
                canvasHash: fingerprintData.data?.canvasFingerprint || 'unknown'
            },
            
            // Browser Details
            browser: fingerprintData.data?.browser || {},
            
            // Connection
            connection: {
                browser: fingerprintData.data?.connection || {},
                server: session.connection || {}
            },
            
            // Locale & Time
            locale: fingerprintData.data?.locale || {},
            
            // Security Assessment
            security: {
                fingerprintHash: crypto.randomBytes(16).toString('hex'),
                trustScore: calculateTrustScore(fingerprintData.data || {}),
                anomalies: session.security?.anomalies || [],
                recommendations: []
            },
            
            // DZBank Internal
            internal: {
                processedBy: 'DZBank Security Engine v3.0',
                analysisTime: Date.now(),
                referenceId: `DZB-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
                compliance: {
                    gdpr: 'PSEUDONYMIZED',
                    pci_dss: 'LEVEL_1',
                    banking_regulation: 'COMPLIANT'
                }
            }
        };
        
        // Store fingerprint
        dzAnalytics.fingerprints.set(profile.security.fingerprintHash, profile);
        dzAnalytics.saveFingerprint(profile.security.fingerprintHash, profile); // Add this line

        
        // Log transaction
        dzAnalytics.logTransaction(fingerprintData.uid, 'FINGERPRINT_COLLECTED', {
            hash: profile.security.fingerprintHash,
            device: `${profile.browser.browser || 'unknown'} on ${profile.browser.platform || 'unknown'}`,
            risk: profile.security.trustScore
        });
        
        console.log('🔐 DZBank Comprehensive Fingerprint:', JSON.stringify(profile, null, 2));
        
        fs.appendFileSync('dzbank_fingerprints.log', JSON.stringify(profile) + '\n');
        
        res.json({
            status: 'success',
            message: 'DZBank Security Data Collected',
            reference: profile.internal.referenceId,
            compliance: profile.internal.compliance
        });
    } catch (error) {
        console.error('Error in collect-fingerprint:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: error.message 
        });
    }
});

// Helper functions
function calculateTrustScore(data) {
    let score = 100;
    
    // Deduct for suspicious patterns
    if (data.browser?.doNotTrack === '1') score -= 10;
    if (data.connection?.effectiveType === '4g') score += 5;
    if (data.connection?.saveData) score -= 5;
    
    return Math.max(0, Math.min(100, score));
}
// Download database endpoint
app.get("/download-database", (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
        res.setHeader('WWW-Authenticate', 'Basic realm="DZBank Security Dashboard"');
        return res.status(401).send('Authentication required');
    }
    
    const auth = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
    const username = auth[0];
    const password = auth[1];
    
    if (username !== 'admin' || password !== 'salmen1234') {
        res.setHeader('WWW-Authenticate', 'Basic realm="DZBank Security Dashboard"');
        return res.status(401).send('Invalid credentials');
    }
    
    const dbPath = 'dzbank_security.db';
    const fileName = `dzbank_backup_${new Date().toISOString().replace(/:/g, '-')}.db`;
    
    res.download(dbPath, fileName, (err) => {
        if (err) {
            console.error('Error downloading database:', err);
            res.status(500).send('Error downloading database');
        }
    });
});

// Analytics Dashboard
// Add this middleware for basic authentication
app.use('/dzbank-dashboard', (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
        res.setHeader('WWW-Authenticate', 'Basic realm="DZBank Security Dashboard"');
        return res.status(401).send('Authentication required');
    }
    
    const auth = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
    const username = auth[0];
    const password = auth[1];
    
    if (username === 'admin' && password === 'salmen1234') {
        next();
    } else {
        res.setHeader('WWW-Authenticate', 'Basic realm="DZBank Security Dashboard"');
        return res.status(401).send('Invalid credentials');
    }
});

// Enhanced Dashboard with Full Data Display
app.get("/dzbank-dashboard", (req, res) => {
    const allSessions = Array.from(dzAnalytics.sessions.values());
    const allFingerprints = Array.from(dzAnalytics.fingerprints.values());
    
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>DZBank Security Analytics Dashboard</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                background: linear-gradient(135deg, #003399 0%, #0066cc 100%);
                color: white;
                padding: 20px;
            }
            
            .dashboard {
                max-width: 1400px;
                margin: 0 auto;
            }
            
            .header {
                background: rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                padding: 30px;
                margin-bottom: 20px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .logo h1 {
                font-size: 32px;
                margin-bottom: 5px;
            }
            
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 20px;
            }
            
            .stat-card {
                background: rgba(255,255,255,0.15);
                backdrop-filter: blur(10px);
                padding: 25px;
                border-radius: 15px;
                text-align: center;
                transition: transform 0.3s, background 0.3s;
                box-shadow: 0 5px 20px rgba(0,0,0,0.2);
            }
            
            .stat-card:hover {
                transform: translateY(-5px);
                background: rgba(255,255,255,0.2);
            }
            
            .stat-label {
                font-size: 14px;
                opacity: 0.9;
                margin-bottom: 10px;
            }
            
            .stat-number {
                font-size: 42px;
                font-weight: bold;
                color: #00ffcc;
            }
            
            .section {
                background: rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
                padding: 25px;
                border-radius: 15px;
                margin-bottom: 20px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.2);
            }
            
            .section h2 {
                margin-bottom: 20px;
                font-size: 24px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .data-container {
                max-height: 600px;
                overflow-y: auto;
                background: rgba(0,0,0,0.3);
                border-radius: 10px;
                padding: 20px;
            }
            
            .data-item {
                background: rgba(255,255,255,0.05);
                border-left: 4px solid #00ffcc;
                padding: 20px;
                margin-bottom: 15px;
                border-radius: 8px;
                transition: background 0.3s;
            }
            
            .data-item:hover {
                background: rgba(255,255,255,0.1);
            }
            
            .data-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
                padding-bottom: 10px;
                border-bottom: 1px solid rgba(255,255,255,0.2);
            }
            
            .session-id {
                font-weight: bold;
                color: #00ffcc;
                font-size: 16px;
            }
            
            .timestamp {
                color: #ffaa00;
                font-size: 14px;
            }
            
            .data-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 15px;
                margin-bottom: 15px;
            }
            
            .data-field {
                background: rgba(0,0,0,0.2);
                padding: 12px;
                border-radius: 6px;
            }
            
            .field-label {
                font-size: 12px;
                opacity: 0.7;
                margin-bottom: 5px;
                text-transform: uppercase;
            }
            
            .field-value {
                font-size: 14px;
                word-break: break-all;
            }
            
            .json-display {
                background: rgba(0,0,0,0.4);
                padding: 15px;
                border-radius: 8px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                overflow-x: auto;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
            
            .risk-badge {
                display: inline-block;
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: bold;
            }
            
            .risk-high { background: #ff4444; }
            .risk-medium { background: #ffaa00; }
            .risk-low { background: #00ffaa; color: #000; }
            
            .anomaly-badge {
                display: inline-block;
                background: #ff4444;
                padding: 4px 10px;
                border-radius: 12px;
                font-size: 11px;
                margin-right: 5px;
                margin-bottom: 5px;
            }
            
            .toggle-btn {
                background: rgba(255,255,255,0.2);
                border: none;
                color: white;
                padding: 8px 20px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 12px;
                transition: background 0.3s;
            }
            
            .toggle-btn:hover {
                background: rgba(255,255,255,0.3);
            }
            
            .tabs {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
            }
            
            .tab {
                background: rgba(255,255,255,0.1);
                padding: 12px 25px;
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.3s;
                border: 2px solid transparent;
            }
            
            .tab:hover {
                background: rgba(255,255,255,0.2);
            }
            
            .tab.active {
                background: rgba(0,255,204,0.2);
                border-color: #00ffcc;
            }
            
            .tab-content {
                display: none;
            }
            
            .tab-content.active {
                display: block;
            }
            
            ::-webkit-scrollbar {
                width: 10px;
            }
            
            ::-webkit-scrollbar-track {
                background: rgba(0,0,0,0.2);
                border-radius: 5px;
            }
            
            ::-webkit-scrollbar-thumb {
                background: rgba(0,255,204,0.5);
                border-radius: 5px;
            }
            
            ::-webkit-scrollbar-thumb:hover {
                background: rgba(0,255,204,0.7);
            }
        </style>
    </head>
    <body>
        <div class="dashboard">
<div class="header">
    <div class="logo">
        <h1>🏦 DZBank Security Analytics</h1>
        <div style="font-size: 14px; opacity: 0.8;">Real-time Fraud Prevention & Monitoring</div>
    </div>
    <div style="text-align: right;">
        <div style="margin-bottom: 10px;">
            <a href="/download-database" style="
                background: rgba(0,255,204,0.2);
                border: 2px solid #00ffcc;
                color: white;
                padding: 10px 20px;
                border-radius: 8px;
                text-decoration: none;
                display: inline-block;
                font-weight: bold;
                transition: all 0.3s;
            " onmouseover="this.style.background='rgba(0,255,204,0.3)'" 
               onmouseout="this.style.background='rgba(0,255,204,0.2)'">
                💾 Download Database
            </a>
        </div>
        <div style="font-size: 12px; opacity: 0.7;">Logged in as: admin</div>
        <div>v3.0 | ${new Date().toLocaleString()}</div>
    </div>
</div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-label">Active Sessions</div>
                    <div class="stat-number">${dzAnalytics.sessions.size}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Fingerprints Collected</div>
                    <div class="stat-number">${dzAnalytics.fingerprints.size}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Total Anomalies</div>
                    <div class="stat-number">${allSessions.reduce((sum, s) => sum + (s.security?.anomalies?.length || 0), 0)}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Average Trust Score</div>
                    <div class="stat-number">${allSessions.length > 0 ? Math.round(allSessions.reduce((sum, s) => sum + (s.security?.trustScore || 0), 0) / allSessions.length) : 0}%</div>
                </div>
            </div>
            
            <div class="section">
                <div class="tabs">
                    <div class="tab active" onclick="switchTab('sessions')">
                        📊 Sessions (${allSessions.length})
                    </div>
                    <div class="tab" onclick="switchTab('fingerprints')">
                        🔍 Fingerprints (${allFingerprints.length})
                    </div>
                </div>
                
                <div id="sessions-tab" class="tab-content active">
                    <h2>🔐 All Session Data</h2>
                    <div class="data-container">
                        ${allSessions.length === 0 ? '<p style="text-align: center; opacity: 0.7;">No sessions recorded yet</p>' : ''}
                        ${allSessions.map((session, index) => `
                            <div class="data-item">
                                <div class="data-header">
                                    <div>
                                        <div class="session-id">Session #${index + 1}: ${session.sessionId || 'Unknown'}</div>
                                        <div style="font-size: 12px; opacity: 0.8; margin-top: 5px;">
                                            User: ${session.uid || 'Anonymous'} | Campaign: ${session.campaign || 'N/A'}
                                        </div>
                                    </div>
                                    <div style="text-align: right;">
                                        <div class="timestamp">${new Date(session.timestamp).toLocaleString()}</div>
                                        <div style="margin-top: 5px;">
                                            <span class="risk-badge risk-${session.security?.trustScore > 70 ? 'low' : session.security?.trustScore > 40 ? 'medium' : 'high'}">
                                                Trust: ${session.security?.trustScore || 0}%
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="data-grid">
                                    <div class="data-field">
                                        <div class="field-label">IP Address</div>
                                        <div class="field-value">${session.ip || 'Unknown'} (${session.network?.ipv || 'Unknown'})</div>
                                    </div>
                                    
                                    <div class="data-field">
                                        <div class="field-label">Location</div>
                                        <div class="field-value">
                                            ${session.geolocation?.country || 'Unknown'} 
                                            ${session.geolocation?.city ? `- ${session.geolocation.city}` : ''}
                                            <br><small>Timezone: ${session.geolocation?.timezone || 'Unknown'}</small>
                                        </div>
                                    </div>
                                    
                                    <div class="data-field">
                                        <div class="field-label">Device</div>
                                        <div class="field-value">
                                            ${session.device?.parsed?.browser || 'Unknown'} ${session.device?.parsed?.version || ''}
                                            <br><small>${session.device?.parsed?.os || 'Unknown OS'} - ${session.device?.parsed?.platform || 'Unknown'}</small>
                                        </div>
                                    </div>
                                    
                                    <div class="data-field">
                                        <div class="field-label">Connection</div>
                                        <div class="field-value">
                                            ${session.connection?.protocol || 'Unknown'}://${session.connection?.host || 'Unknown'}
                                            <br><small>Secure: ${session.connection?.secure ? 'Yes' : 'No'}</small>
                                        </div>
                                    </div>
                                </div>
                                
                                ${session.security?.anomalies?.length > 0 ? `
                                    <div style="margin-top: 15px;">
                                        <div class="field-label">⚠️ Security Anomalies</div>
                                        <div style="margin-top: 8px;">
                                            ${session.security.anomalies.map(a => `<span class="anomaly-badge">${a}</span>`).join('')}
                                        </div>
                                    </div>
                                ` : ''}
                                
                                <div style="margin-top: 15px;">
                                    <button class="toggle-btn" onclick="toggleJson('session-${index}')">
                                        📋 View Complete JSON Data
                                    </button>
                                    <div id="session-${index}" class="json-display" style="display: none; margin-top: 10px;">
${JSON.stringify(session, null, 2)}
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                
                <div id="fingerprints-tab" class="tab-content">
                    <h2>🔍 All Fingerprint Data</h2>
                    <div class="data-container">
                        ${allFingerprints.length === 0 ? '<p style="text-align: center; opacity: 0.7;">No fingerprints collected yet</p>' : ''}
                        ${allFingerprints.map((fp, index) => `
                            <div class="data-item">
                                <div class="data-header">
                                    <div>
                                        <div class="session-id">Fingerprint #${index + 1}</div>
                                        <div style="font-size: 12px; opacity: 0.8; margin-top: 5px;">
                                            Reference: ${fp.internal?.referenceId || 'Unknown'}
                                        </div>
                                    </div>
                                    <div style="text-align: right;">
                                        <div class="timestamp">${new Date(fp.timestamp).toLocaleString()}</div>
                                        <div style="margin-top: 5px;">
                                            <span class="risk-badge risk-${fp.security?.trustScore > 70 ? 'low' : fp.security?.trustScore > 40 ? 'medium' : 'high'}">
                                                Trust: ${fp.security?.trustScore || 0}%
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="data-grid">
                                    <div class="data-field">
                                        <div class="field-label">Hardware</div>
                                        <div class="field-value">
                                            CPU: ${fp.hardware?.cpu?.cores || 'Unknown'} cores (${fp.hardware?.cpu?.architecture || 'Unknown'})
                                            <br>Memory: ${fp.hardware?.cpu?.memory || 'Unknown'} GB
                                        </div>
                                    </div>
                                    
                                    <div class="data-field">
                                        <div class="field-label">GPU</div>
                                        <div class="field-value">
                                            ${fp.hardware?.gpu?.vendor || 'Unknown'}
                                            <br><small>${fp.hardware?.gpu?.renderer ? fp.hardware.gpu.renderer.substring(0, 50) : 'Unknown'}...</small>
                                        </div>
                                    </div>
                                    
                                    <div class="data-field">
                                        <div class="field-label">Screen</div>
                                        <div class="field-value">
                                            ${fp.display?.screen?.width || 0}x${fp.display?.screen?.height || 0}
                                            <br><small>Color Depth: ${fp.display?.screen?.colorDepth || 'Unknown'}-bit | DPR: ${fp.display?.screen?.devicePixelRatio || 1}</small>
                                        </div>
                                    </div>
                                    
                                    <div class="data-field">
                                        <div class="field-label">Browser</div>
                                        <div class="field-value">
                                            ${fp.browser?.platform || 'Unknown'}
                                            <br><small>Language: ${fp.browser?.language || 'Unknown'} | Cookies: ${fp.browser?.cookieEnabled ? 'Enabled' : 'Disabled'}</small>
                                        </div>
                                    </div>
                                    
                                    <div class="data-field">
                                        <div class="field-label">Connection</div>
                                        <div class="field-value">
                                            ${fp.connection?.browser?.effectiveType || 'Unknown'}
                                            <br><small>RTT: ${fp.connection?.browser?.rtt || 'Unknown'}ms | Downlink: ${fp.connection?.browser?.downlink || 'Unknown'} Mbps</small>
                                        </div>
                                    </div>
                                    
                                    <div class="data-field">
                                        <div class="field-label">Locale</div>
                                        <div class="field-value">
                                            Timezone: ${fp.locale?.timezone || 'Unknown'}
                                            <br><small>Language: ${fp.locale?.locale || 'Unknown'}</small>
                                        </div>
                                    </div>
                                </div>
                                
                                <div style="margin-top: 15px;">
                                    <button class="toggle-btn" onclick="toggleJson('fingerprint-${index}')">
                                        📋 View Complete JSON Data
                                    </button>
                                    <div id="fingerprint-${index}" class="json-display" style="display: none; margin-top: 10px;">
${JSON.stringify(fp, null, 2)}
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            function toggleJson(id) {
                const element = document.getElementById(id);
                if (element.style.display === 'none') {
                    element.style.display = 'block';
                } else {
                    element.style.display = 'none';
                }
            }
            
            function switchTab(tabName) {
                // Hide all tabs
                document.querySelectorAll('.tab-content').forEach(tab => {
                    tab.classList.remove('active');
                });
                document.querySelectorAll('.tab').forEach(tab => {
                    tab.classList.remove('active');
                });
                
                // Show selected tab
                document.getElementById(tabName + '-tab').classList.add('active');
                event.target.classList.add('active');
            }
            
            // Auto-refresh every 30 seconds
            setTimeout(() => {
                location.reload();
            }, 30000);
        </script>
    </body>
    </html>
    `);
});

// Test endpoints
app.get("/test-pixel", (req, res) => {
    res.send(`
    <html>
    <head><title>DZBank Security Test</title></head>
    <body>
        <h1>DZBank Security Analytics Test</h1>
        <p>This page includes the tracking pixel and fingerprint script.</p>
        <img src="/pixel.png?uid=test_user_001&campaign=security_test" width="1" height="1">
        <script src="/fingerprint.js?uid=test_user_001"></script>
        <script src="/webrtc-ip.js?uid=test_user_001"></script>

        <p>Check console for output and visit <a href="/dzbank-dashboard">Dashboard</a></p>
    </body>
    </html>
    `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🏦 DZBank Security Analytics Server running on port ${PORT}`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dzbank-dashboard`);
    console.log(`🧪 Test Page: http://localhost:${PORT}/test-pixel`);
});


