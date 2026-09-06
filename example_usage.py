import json
from client import AgentEphemeralNetworkEgressFirewall

def main():
    firewall = AgentEphemeralNetworkEgressFirewall()
    
    # 1. Legitimate PyPI egress
    r1 = firewall.evaluate_egress_request("files.pythonhosted.org", 443)
    print("PyPI Egress:", json.dumps(r1))
    assert r1["decision"] == "ALLOWED"
    
    # 2. SSRF attack on cloud metadata service
    r2 = firewall.evaluate_egress_request("169.254.169.254", 80)
    print("Metadata Egress:", json.dumps(r2))
    assert r2["decision"] == "BLOCKED"
    assert "metadata" in r2["reason"]
    
    # 3. Unauthorized third party domain
    r3 = firewall.evaluate_egress_request("malicious-exfiltration.xyz", 443)
    print("Exfiltration Egress:", json.dumps(r3))
    assert r3["decision"] == "BLOCKED"
    
    print("Egress firewall verification complete: PASS")

if __name__ == "__main__":
    main()
