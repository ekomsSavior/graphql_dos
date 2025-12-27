# GRAPHQL DoS ASSESSMENT TOOL v3.0

## THE WEAPON

This is not another "security assessment" tool. This is a precision instrument designed to find and exploit GraphQL endpoints until they scream for mercy.

## WHAT THIS THING DOES

### Reconnaissance That Actually Works
- 9 different HTTP methods (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE, CONNECT)
- 15+ content types (application/json, application/graphql, text/plain, and shit you've never heard of)
- 30+ WAF bypass headers (X-Forwarded-For, X-Real-IP, X-HTTP-Method-Override, etc.)
- 28+ subdomain combinations (api., graphql., data., etc.)
- Multiple parameter formats (JSON, GraphQL string, URL-encoded, XML, multipart)

### Attack Vectors That Actually Hurt
Once we find a working endpoint (and we WILL find one), we hit it with:

1. **Lightning Strike** - Fast, aggressive DoS with configurable threads and duration
2. **Vortex Attack** - Multi-vector saturation (7 attack vectors simultaneously)
3. **Apocalypse Mode** - Maximum destruction (socket floods, connection exhaustion, memory attacks)
4. **Precision Strike** - Target specific GraphQL vulnerabilities:
   - Query depth limitation bypass (test up to 200 levels)
   - Field duplication attacks (up to 5000 duplicate fields)
   - Alias overload (1000+ aliases)
   - Directive floods (500+ directives)
   - Fragment recursion attacks
   - Union/interface abuse
   - Variable bombs (30+ large variables)
   - Introspection exploitation
   - Batch query attacks
   - Persisted query attacks

5. **Endless Torment** - Sustained attacks:
   - Low & Slow (stealth mode)
   - Pulsed attacks (bursts with pauses)
   - Randomized patterns (unpredictable)
   - Escalating intensity (gradual increase)

6. **Impact Assessment** - Measure before/after performance to prove the damage

### Advanced Features
- WebSocket attack testing
- DNS rebinding concepts
- Schema introspection extraction
- Subscription endpoint discovery
- Full comprehensive attack mode (everything at once)

## INSTALLATION 

### Step 1: Clone This Repo
```bash
git clone https://github.com/ekomsSavior/graphql_dos.git
cd graphql_dos
```

### Step 2: Install Requirements

```bash
pip install requests websocket-client --break-system-packages
```

### Step 3: Run The Damn Thing

```bash
python3 graphql_dos.py
```

## HOW TO USE THIS PROPERLY

### Basic Usage
1. Run the script
2. Enter target URL (e.g., `https://target.com` or just `target.com`)
3. Let it discover working endpoints (it handles 405s automatically)
4. Choose your attack mode
5. Watch the magic happen

### Advanced Targeting
The tool automatically discovers:
- Working GraphQL endpoints
- Correct HTTP methods
- Valid content types
- WAF bypass headers
- Subdomains with GraphQL

### Attack Configuration
Each attack mode has configurable options:
- Duration (seconds or minutes)
- Intensity (thread count)
- Attack vectors (which techniques to use)
- Monitoring (real-time stats)

### Reading The Output
- Green checkmarks (✓) mean success
- HTTP status codes tell you what's happening
- Response times show performance impact
- Error messages indicate vulnerabilities
- Final report summarizes everything

## REAL-WORLD USAGE EXAMPLES

### Example 1: Basic Reconnaissance
```bash
python graphql_dos.py
# Enter: https://vulnerable-target.com
# Choose: 1 (Reconnaissance Only)
# Let it find working endpoints
```

### Example 2: Full 405 Bypass Test
```bash
python graphql_dos.py
# Enter: https://target-with-waf.com
# Choose: 13 (Advanced 405 Bypass)
# Watch it try every bypass technique
```

### Example 3: Precision Strike
```bash
python graphql_dos.py
# Enter: https://api.target.com
# Choose: 4 (Precision Strike)
# Select: 9 (All Precision Attacks)
# Tests every GraphQL vulnerability
```

### Example 4: Full Attack
```bash
python graphql_dos.py
# Enter: https://production-api.com
# Choose: 20 (Full Comprehensive Attack)
# Goes through every technique in order
```

## UNDERSTANDING THE ATTACK MODES

### Mode 1-6: Reconnaissance & Bypass
These modes find working endpoints and bypass protections. Use these first.

### Mode 7-11: Direct Attacks
Lightning, Vortex, Apocalypse - these are your main weapons. Choose based on how loud you want to be.

### Mode 12-20: Advanced Techniques
Precision strikes, WebSockets, subscriptions, DNS concepts - for when you need to get creative.

## WHAT TO LOOK FOR IN RESULTS

### Indicators of Vulnerability
- Response times increasing under load
- 429 (rate limit) responses
- 503 (service unavailable) responses
- Timeouts
- GraphQL error messages about complexity/depth
- Successful introspection queries
- Accepted batch queries
- Working with unusual HTTP methods

### Proof for Reports
The tool generates a report with:
- Target information
- Request statistics
- Attack results
- Impact indicators
- Bounty submission checklist

## DISCLAIMER 

I'm providing this tool for EDUCATIONAL PURPOSES ONLY. This means:

1. **LEGAL USE ONLY**: Only test systems you OWN or have EXPLICIT WRITTEN PERMISSION to test.
2. **NO ILLEGAL ACTIVITY**: Don't be stupid. Unauthorized testing is a crime.
3. **YOU ARE RESPONSIBLE**: If you use this tool illegally, that's on you. I'm not your lawyer.
4. **ETHICAL TESTING ONLY**: Follow responsible disclosure. Find bugs, report them properly.
5. **NO WARRANTIES**: This tool might not work, might break things, might get you in trouble. Use at your own risk.

If you can't understand these basic rules, you shouldn't be anywhere near security tools.

## TROUBLESHOOTING

### Common Issues and Solutions

**Issue**: Getting only 405 responses
**Solution**: The tool handles this automatically. It tries multiple methods, headers, and content types. If it still fails, the target might have very strong WAF.

**Issue**: Connection timeouts
**Solution**: Increase timeouts in the code or check your network. Some targets are slow.

**Issue**: SSL certificate errors
**Solution**: The tool ignores SSL verification by default. If you need to verify certs, modify the code.

**Issue**: Rate limiting
**Solution**: That's a feature, not a bug. It means the attack is working. The tool detects and reports rate limits.


## FOR MAXIMUM IMPACT

1. **Recon First**: Always start with reconnaissance (Mode 1-6)
2. **Find Weaknesses**: Use precision strikes (Mode 4, 10) to identify specific vulnerabilities
3. **Calibrate Attacks**: Use impact assessment (Mode 6, 12) to measure effectiveness
4. **Scale Up**: Once you know what works, hit it hard (Mode 7-9)
5. **Document Everything**: Use the generated reports for proof

## FINAL NOTES

This tool is maintained by one person. There's no team, no support line, no hand-holding. If you find bugs, you can fix them yourself. If you want features, build them yourself. This is a tool for professionals who know what they're doing.

The code is provided as-is. It works for me. It should work for you. If it doesn't, figure it out.

by: ek0ms savi0r CEH lone wolf cyber priestess
<img width="500" height="500" alt="Untitled_Artwork" src="https://github.com/user-attachments/assets/ec41aeb9-9ea6-42a3-8104-6df149d70942" />

