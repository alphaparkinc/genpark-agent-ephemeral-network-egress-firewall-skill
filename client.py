import ipaddress
from typing import Dict, Any, List, Optional

class AgentEphemeralNetworkEgressFirewall:
    """
    Validates outbound connection destinations (IPs and hostnames) against cloud metadata blacklists
    and package repository allowlists.
    """
    PROHIBITED_METADATA_IPS = [
        "169.254.169.254",  # AWS/GCP/Azure instance metadata
        "127.0.0.1",        # Localhost loopback
        "10.0.0.0/8",       # Internal VPC
        "192.168.0.0/16"    # Internal LAN
    ]

    DEFAULT_ALLOWED_DOMAINS = [
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "github.com",
        "api.github.com",
        "huggingface.co",
        "crates.io"
    ]

    def evaluate_egress_request(self, destination: str, port: int = 443) -> Dict[str, Any]:
        dest_clean = destination.strip().lower()

        # 1. Check if destination is IP address
        try:
            ip_obj = ipaddress.ip_address(dest_clean)
            for prohibited in self.PROHIBITED_METADATA_IPS:
                if "/" in prohibited:
                    net = ipaddress.ip_network(prohibited)
                    if ip_obj in net:
                        return {
                            "destination": destination,
                            "port": port,
                            "decision": "BLOCKED",
                            "reason": f"Destination falls within forbidden internal subnet {prohibited}"
                        }
                elif str(ip_obj) == prohibited:
                    return {
                        "destination": destination,
                        "port": port,
                        "decision": "BLOCKED",
                        "reason": f"Destination matches cloud metadata / loopback IP {prohibited}"
                    }
            return {
                "destination": destination,
                "port": port,
                "decision": "BLOCKED_BY_DEFAULT",
                "reason": "Raw IP connection prohibited; must connect via allowed domain."
            }
        except ValueError:
            # Destination is a domain name
            pass

        # 2. Domain Allowlist Check
        is_allowed = any(dest_clean == domain or dest_clean.endswith("." + domain) for domain in self.DEFAULT_ALLOWED_DOMAINS)
        
        if is_allowed and port in [80, 443]:
            return {
                "destination": destination,
                "port": port,
                "decision": "ALLOWED",
                "reason": "Destination verified on trusted package registry allowlist."
            }
        else:
            return {
                "destination": destination,
                "port": port,
                "decision": "BLOCKED",
                "reason": f"Domain '{dest_clean}' or port {port} is not on the outbound firewall allowlist."
            }
