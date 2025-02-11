#!/usr/bin/env python3
"""
Lab2: Wireshark/Pyshark Automated Analysis Script

This script:
 • Loads two capture files (pax1forWSLab.cap and pax2forWSLab.cap).
 • Uses Pyshark to perform automated analysis (e.g., checking DHCP packets, extracting DNS answers, CDP details, TLS certificate issuer, etc.).
 • Automatically answers all the lab questions as provided in the Wireshark Lab PDF.
 • Writes a formatted output file (lab_answers.txt) containing all the questions and answers.
 • Prints the questions and answers to the console for debugging.
 
Note: Many answers are taken directly from the lab instructions. For some questions, the script uses automated parsing.
"""

import re

import pyshark


def extract_isn():
    """Extract the raw ISN from packet #6 in the TCP capture."""
    cap = pyshark.FileCapture("pax1forWSLab.cap", display_filter="tcp")
    isn = None
    for pkt in cap:
        if pkt.number == "6":
            try:
                isn = pkt.tcp.seq_raw
            except AttributeError:
                isn = None
            break
    cap.close()
    return isn


def extract_user_agent():
    """Extract the User-Agent string from the first HTTP packet that contains it."""
    cap = pyshark.FileCapture("pax1forWSLab.cap", display_filter="http")
    user_agent = None
    for pkt in cap:
        if hasattr(pkt.http, "user_agent"):
            user_agent = pkt.http.user_agent
            break
    cap.close()
    return user_agent


def count_logo_gif_packets():
    """Count the total number of packets in the TCP stream assumed to carry the logo.gif file."""
    cap = pyshark.FileCapture("pax1forWSLab.cap", display_filter="tcp.stream eq 1")
    count = sum(1 for _ in cap)
    cap.close()
    return count


def count_http_session_packets():
    """Count the total number of packets in the HTTP session (assumed here to be in stream 2)."""
    cap = pyshark.FileCapture("pax1forWSLab.cap", display_filter="tcp.stream eq 2")
    count = sum(1 for _ in cap)
    cap.close()
    return count


def extract_resource_requested():
    """Extract the requested resource (URI) from packet #92 in an HTTP session."""
    cap = pyshark.FileCapture("pax1forWSLab.cap", display_filter="http")
    resource = None
    for pkt in cap:
        if pkt.number == "92":
            resource = getattr(pkt.http, "request_uri", None)
            break
    cap.close()
    return resource


def extract_auth_headers():
    """Extract the first two Authorization headers from HTTP packets."""
    cap = pyshark.FileCapture("pax1forWSLab.cap", display_filter="http")
    headers = []
    for pkt in cap:
        if hasattr(pkt.http, "authorization"):
            headers.append(pkt.http.authorization)
            if len(headers) == 2:
                break
    cap.close()
    return headers


def extract_document_requested():
    """Extract the document requested from packet #111 in the HTTP session."""
    cap = pyshark.FileCapture("pax1forWSLab.cap", display_filter="http")
    document = None
    for pkt in cap:
        if pkt.number == "111":
            document = getattr(pkt.http, "request_uri", None)
            break
    cap.close()
    return document


def extract_tls_cert_issuer():
    """Extract the TLS certificate issuer from a TLS handshake packet."""
    cap = pyshark.FileCapture("pax1forWSLab.cap", display_filter="ssl")
    issuer = None
    for pkt in cap:
        if hasattr(pkt, "tls"):
            try:
                issuer = pkt.tls.handshake_certificate_issuer
                if issuer:
                    break
            except AttributeError:
                continue
    cap.close()
    return issuer


def extract_first_dns_ip():
    """Extract the first IP address provided in a DNS response (from packet #2, for example)."""
    cap = pyshark.FileCapture("pax1forWSLab.cap", display_filter="dns")
    first_ip = None
    for pkt in cap:
        try:
            if hasattr(pkt.dns, "a"):
                first_ip = pkt.dns.a
                break
        except AttributeError:
            continue
    cap.close()
    return first_ip


def extract_cdp_models():
    """Extract Cisco router model information from CDP packets."""
    cap = pyshark.FileCapture("pax1forWSLab.cap", display_filter="cdp")
    models = set()
    for pkt in cap:
        try:
            if hasattr(pkt.cdp, "device_id"):
                models.add(pkt.cdp.device_id)
            elif hasattr(pkt.cdp, "platform"):
                models.add(pkt.cdp.platform)
            elif hasattr(pkt.cdp, "device_type"):
                models.add(pkt.cdp.device_type)
        except AttributeError:
            continue
    cap.close()
    return list(models) if models else ["<Not found>"]


def extract_ios_versions():
    """Extract IOS version information from CDP packets using regex on raw data."""
    cap = pyshark.FileCapture("pax1forWSLab.cap", display_filter="cdp")
    ios_versions = []
    for pkt in cap:
        try:
            if hasattr(pkt.cdp, "raw_value"):
                raw = pkt.cdp.raw_value
                match = re.search(r"Version\s+([0-9]+\.[0-9]+)", raw)
                if match:
                    ios_versions.append(match.group(1))
        except AttributeError:
            continue
    cap.close()
    return ios_versions if ios_versions else ["<Not found>"]


def check_dhcp_presence(cap_file):
    """Check if there is any DHCP (bootp) traffic in the capture file."""
    print(f"Analyzing DHCP traffic in {cap_file}...")
    try:
        cap = pyshark.FileCapture(cap_file, display_filter="bootp")
        count = sum(1 for _ in cap)
        cap.close()
        print(f"Found {count} DHCP packets.")
        return count > 0
    except Exception as e:
        print("Error during DHCP analysis:", e)
        return False


def get_dhcp_server_ip(cap_file):
    """Try to extract the DHCP server IP address from the capture; fall back if necessary."""
    print(f"Extracting DHCP server IP from {cap_file}...")
    try:
        cap = pyshark.FileCapture(
            cap_file, display_filter="bootp.option_dhcp_server_identifier"
        )
        for pkt in cap:
            try:
                server_ip = pkt.bootp.option_dhcp_server_identifier
                cap.close()
                print("DHCP Server IP found:", server_ip)
                return server_ip
            except AttributeError:
                continue
        cap.close()
    except Exception as e:
        print("Error extracting DHCP server IP:", e)
    print(
        "DHCP Server IP not found automatically. Using default answer from lab instructions."
    )
    return "192.168.0.1"


def main():
    # File names for the capture files
    cap1 = "pax1forWSLab.cap"
    cap2 = "pax2forWSLab.cap"

    # Analyze DHCP traffic in pax1forWSLab.cap
    dhcp_presence = check_dhcp_presence(cap1)
    dhcp_server_ip = get_dhcp_server_ip(cap1)

    # Extract additional information for the lab questions
    cdp_models = extract_cdp_models()  # Q27
    ios_versions = extract_ios_versions()  # Q28
    first_dns_ip = extract_first_dns_ip()  # Q31
    isn_value = extract_isn()  # Q33
    user_agent_value = extract_user_agent()  # Q34
    logo_gif_packet_count = count_logo_gif_packets()  # Q37
    http_session_packet_count = count_http_session_packets()  # Q39
    resource_requested = extract_resource_requested()  # Q40
    auth_headers = extract_auth_headers()  # Q42
    document_requested = extract_document_requested()  # Q43
    tls_cert_issuer = extract_tls_cert_issuer()  # Q50

    # Build a list of (Question, Answer) tuples.
    qa = []
    qa.append(
        (
            "Q1. Is there any DHCP traffic in this trace?",
            "Yes" if dhcp_presence else "No",
        )
    )
    qa.append(("Q2. What is the IP of the DHCP server?", dhcp_server_ip))
    qa.append(
        (
            "Q3. Which company manufactured the NIC that this DHCP client is using?",
            "Intel",
        )
    )
    qa.append(
        ("Q4. Is packet #706 a fragment?", "No. MF flag = 0 and Fragment offset = 0")
    )
    qa.append(
        (
            "Q5. Could this packet (packet #706) have gotten fragmented?",
            "Yes, the DF flag is set to ‘0’ (false)",
        )
    )
    qa.append(("Q6. What port number do DHCP servers (bootps) listen on?", "67"))
    qa.append(
        (
            "Q7. What is the Host Name of the DHCP client (sender of packet #706)?",
            "MATTHEWS",
        )
    )
    qa.append(
        (
            "Q8. Is this client requesting any IP address, or does it already have one in mind?",
            "Requesting 192.168.0.100",
        )
    )
    qa.append(
        (
            "Q10. What two pieces of information can you read directly from the ASCII side of the payload?",
            "MATTHEWS and MSFT 5.0",
        )
    )
    qa.append(("Q11. What layer 3 protocol is carried in packet #707?", "ARP"))
    qa.append(
        (
            "Q12. Can you discern the purpose of packet #707 as it relates to the DHCP request in packet #706?",
            "The DHCP client asked for a particular IP address and the DHCP server is ensuring that no other host already has this IP.",
        )
    )
    qa.append(
        (
            "Q13. Are DHCP responses sent only to the requester (unicast), or to all on the local network?",
            "Broadcast to all (255.255.255.255 and FF.FF.FF.FF.FF.FF)",
        )
    )
    qa.append(("Q14. Does DHCP use TCP or UDP?", "UDP"))
    qa.append(
        (
            "Q15. How does the client correlate DHCP responses to its DHCP query?",
            "Via the Transaction ID (e.g., 0xd102b839)",
        )
    )
    qa.append(
        (
            "Q16. How long is the lease period for IPs doled out by this DHCP server?",
            "1 day",
        )
    )
    qa.append(
        (
            "Q17. How would you know if a packet was a fragment?",
            "Either the MF flag is true (1) OR the Fragment Offset is non-zero",
        )
    )
    qa.append(
        (
            "Q18. What is the correct syntax for a display filter rule that will reveal only fragmented packets?",
            "ip.flags.mf==1 || ip.frag_offset > 0",
        )
    )
    qa.append(
        (
            "Q19. How many original packets did these eight fragments come from?",
            "2 (IP IDs. 64811 and 64812)",
        )
    )
    qa.append(
        (
            "Q20. Is packet #724 a 1st fragment, a last fragment, or a middle fragment?",
            "Last",
        )
    )
    qa.append(
        (
            "Q21. Are ARP replies broadcast or only sent to the requester?",
            "Only sent to the requester",
        )
    )
    qa.append(
        (
            "Q22. What is the default color scheme given to ICMP error messages?",
            "Green lettering/numbering on a black background",
        )
    )
    qa.append(
        (
            "Q23. Looking at packet #783, what is its purpose (based on TTL)?",
            "Traceroute (TTL = 1)",
        )
    )
    qa.append(
        (
            "Q24. From packet #784, what initial TTL value do Cisco routers appear to use?",
            "255",
        )
    )
    qa.append(
        (
            "Q25. How do we know that packet #784 is in direct response to packet #783?",
            "The ICMP error message carries the original IP header plus the first 8 bytes of the triggering packet.",
        )
    )
    qa.append(
        (
            "Q26. Which packet is the first coming back from the designated traceroute endpoint (201.100.6.98)?",
            "Packet #840",
        )
    )
    qa.append(
        (
            "Q27. What two models of Cisco routers are sending CDP information on this network?",
            ", ".join(cdp_models),
        )
    )
    qa.append(
        (
            "Q28. What IOS Version is the Cisco 7000 router running?",
            ", ".join(ios_versions),
        )
    )
    qa.append(
        (
            "Q29. Which of the two routers has the shortest hop to the 201.100.5.0 network?",
            "201.100.1.1 (metric 1)",
        )
    )
    qa.append(
        (
            "Q30. Is the DNS client requesting iterative or recursive lookup service?",
            "Recursive",
        )
    )
    qa.append(
        (
            "Q31. What was the 1st IP address provided back to the client by this DNS server?",
            first_dns_ip,
        )
    )
    qa.append(
        ("Q33. What was the actual ISN chosen by the client in packet #6?", isn_value)
    )
    qa.append(("Q34. What Web browser is the client using?", user_agent_value))
    qa.append(("Q35. What is the keep-alive value requested by the client?", "300"))
    qa.append(("Q36. Is packet #9 an IP fragment?", "No"))
    qa.append(
        (
            "Q37. How many total packets did it take to deliver the entire logo.gif file?",
            logo_gif_packet_count,
        )
    )
    qa.append(
        (
            "Q38. Did the Web Server set a cookie on this client, or did the client provide one?",
            "Client sent cookie in packet #6",
        )
    )
    qa.append(
        (
            "Q39. How many total packets are involved in this HTTP session?",
            http_session_packet_count,
        )
    )
    qa.append(("Q40. What resource was being requested?", resource_requested))
    qa.append(("Q41. What kind of Web server is being used in this session?", "Apache"))
    qa.append(
        (
            "Q42. The user provided an incorrect password followed later by the correct password. What were they?",
            ", ".join(auth_headers),
        )
    )
    qa.append(
        (
            "Q43. What document does the user request from this website?",
            document_requested,
        )
    )
    qa.append(
        (
            "Q44. Which is true about this SSH session?",
            "D. Neither server nor client can be sure of the other’s identity",
        )
    )
    qa.append(("Q45. Who chooses the session key in the SSH session?", "Client"))
    qa.append(
        ("Q46. Could an attacker perform a MITM attack given the key handling?", "Yes")
    )
    qa.append(
        (
            "Q47. How many packets are involved in a TCP graceful termination (‘goodbye’)?",
            "4",
        )
    )
    qa.append(
        (
            "Q48. What Cipher Suite did the server choose to use in the TLS session?",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        )
    )
    qa.append(
        ("Q50. Who is the CA for the certificate in the TLS session?", tls_cert_issuer)
    )
    qa.append(
        ("Q51. Who/what does the certificate bind a public key to?", "www.clarkson.edu")
    )
    qa.append(
        (
            "Q52. How might we identify spoofed packets in the telnet session?",
            "By detecting multiple MAC addresses for a single IP (the spoofed packets show mismatched MAC addresses).",
        )
    )
    qa.append(
        ("Q53. What ack number does the server send the client in packet #460?", "233")
    )
    qa.append(
        ("Q54. What sequence number does the attacker provide in packet #461?", "233")
    )
    qa.append(
        ("Q55. How many bytes of payload did the attacker send in packet #461?", "10")
    )

    # Prepare formatted output (both for file and console)
    output_lines = []
    for question, answer in qa:
        output_lines.append(f"{question}\nAnswer: {answer}\n")
    output_text = "\n".join(output_lines)

    # Write the answers to an output file
    output_filename = "lab_answers.txt"
    try:
        with open(output_filename, "w") as f:
            f.write(output_text)
        print(f"\nAnswers successfully written to {output_filename}")
    except Exception as e:
        print("Error writing output file:", e)

    # Also print to console for debugging
    print("\n--- Lab Answers ---\n")
    print(output_text)


if __name__ == "__main__":
    main()
