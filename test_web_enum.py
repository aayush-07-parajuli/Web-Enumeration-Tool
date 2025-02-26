import unittest
from unittest.mock import patch, MagicMock
import socket
import requests
import whois
import dns.resolver
from web_enum_gui import (
    enumerate_subdomains,
    enumerate_directories,
    analyze_http_headers,
    perform_whois_lookup,
    scan_ports,
    perform_dns_lookup
)

class TestWebEnumFunctions(unittest.TestCase):

    @patch('requests.get')
    def test_enumerate_subdomains(self, mock_get):
        """Test subdomain enumeration with mock responses."""
        mock_get.side_effect = [MagicMock(status_code=200)] + [MagicMock(status_code=404)] * 5
        result = enumerate_subdomains("example.com")
        self.assertIn("http://admin.example.com", result)

    @patch('requests.get')
    def test_enumerate_directories(self, mock_get):
        """Test directory enumeration with mock responses."""
        mock_get.side_effect = [MagicMock(status_code=200)] + [MagicMock(status_code=404)] * 4
        result = enumerate_directories("example.com")
        self.assertIn("http://example.com/admin/", result)

    @patch('requests.get')
    def test_analyze_http_headers(self, mock_get):
        """Test HTTP header analysis."""
        mock_response = MagicMock()
        mock_response.headers = {"Content-Type": "text/html", "X-Frame-Options": "DENY"}
        mock_get.return_value = mock_response
        result = analyze_http_headers("example.com")
        self.assertIn("Content-Type: text/html", result)
        self.assertIn("X-Frame-Options: DENY", result)

    @patch('whois.query')
    def test_perform_whois_lookup(self, mock_whois):
        """Test WHOIS lookup with mocked response."""
        mock_domain_info = MagicMock()
        mock_domain_info.name = "example.com"
        mock_domain_info.registrar = "Example Registrar"
        mock_domain_info.creation_date = "2022-01-01"
        mock_domain_info.expiration_date = "2025-01-01"
        mock_whois.return_value = mock_domain_info

        result = perform_whois_lookup("example.com")

        print(f"WHOIS result: {result}")  # Debugging output

        self.assertIn("Domain: example.com", result)
        self.assertIn("Registrar: Example Registrar", result)
        self.assertIn("Created: 2022-01-01", result)
        self.assertIn("Expires: 2025-01-01", result)

    @patch('socket.gethostbyname')
    @patch('socket.socket')
    def test_scan_ports(self, mock_socket, mock_gethostbyname):
        """Test port scanning with mock sockets."""
        mock_gethostbyname.return_value = "127.0.0.1"
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.connect_ex.side_effect = [0, 1, 1, 0, 1, 0]  # Open ports: 21, 25, 80
        result = scan_ports("example.com")
        self.assertIn("21", result)
        self.assertIn("25", result)
        self.assertIn("80", result)

    @patch('dns.resolver.resolve')
    def test_perform_dns_lookup(self, mock_resolve):
        """Test DNS lookup with mocked responses."""
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "127.0.0.1"
        mock_resolve.return_value = [mock_answer]
        result = perform_dns_lookup("example.com")
        self.assertIn("A: 127.0.0.1", result)

if __name__ == '__main__':
    unittest.main()
