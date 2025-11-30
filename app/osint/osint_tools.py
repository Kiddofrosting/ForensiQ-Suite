"""
Enhanced OSINT Tools Module - Improved with better error handling and more features
"""

import whois
import dns.resolver
import dns.reversename
import socket
import hashlib
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from email_validator import validate_email, EmailNotValidError
import re
from datetime import datetime
import json
import time

class EnhancedOSINTTools:
    """Enhanced OSINT tools with improved functionality"""

    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 10
        self.dns_resolver.lifetime = 10
        # Common DNS servers as fallback
        self.dns_resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']

        # User agent for web requests
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

    def whois_lookup(self, domain):
        """
        Enhanced WHOIS domain lookup with better error handling
        """
        try:
            domain = self._clean_domain(domain)

            print(f"🔍 Performing WHOIS lookup for: {domain}")
            w = whois.whois(domain)

            result = {
                'domain_name': self._safe_extract(w.domain_name),
                'registrar': w.registrar or 'Not available',
                'creation_date': self._format_date(w.creation_date),
                'expiration_date': self._format_date(w.expiration_date),
                'updated_date': self._format_date(w.updated_date),
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                'emails': w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
                'country': w.country or 'Not available',
                'state': w.state or 'Not available',
                'city': w.city or 'Not available',
                'organization': w.org or 'Not available',
                'registrant_name': getattr(w, 'name', 'Not available'),
                'dnssec': w.dnssec or 'Not available',
                'query_time': datetime.utcnow().isoformat(),
                'raw_data': str(w)
            }

            # Calculate domain age
            if result['creation_date'] != 'Not available':
                try:
                    created = datetime.fromisoformat(result['creation_date'])
                    age_days = (datetime.utcnow() - created).days
                    result['domain_age_days'] = age_days
                    result['domain_age_years'] = round(age_days / 365.25, 1)
                except:
                    pass

            print(f"✓ WHOIS lookup successful")
            return result

        except Exception as e:
            error_msg = str(e)
            print(f"❌ WHOIS lookup failed: {error_msg}")
            return {
                'error': f'WHOIS lookup failed: {error_msg}',
                'domain': domain,
                'suggestion': 'Verify domain name is correct and publicly registered'
            }

    def dns_lookup(self, domain):
        """
        Enhanced DNS record lookup with more record types
        """
        try:
            domain = self._clean_domain(domain)
            print(f"🔍 Performing DNS lookup for: {domain}")

            results = {
                'domain': domain,
                'query_time': datetime.utcnow().isoformat(),
                'records': {},
                'summary': {}
            }

            # Record types to query
            record_types = {
                'A': 'IPv4 addresses',
                'AAAA': 'IPv6 addresses',
                'MX': 'Mail servers',
                'NS': 'Name servers',
                'TXT': 'Text records',
                'SOA': 'Start of authority',
                'CNAME': 'Canonical name',
                'PTR': 'Pointer record',
                'CAA': 'Certificate authority',
                'SRV': 'Service records'
            }

            for record_type, description in record_types.items():
                try:
                    if record_type == 'A':
                        records = self.dns_resolver.resolve(domain, 'A')
                        results['records']['A'] = [str(r) for r in records]

                    elif record_type == 'AAAA':
                        records = self.dns_resolver.resolve(domain, 'AAAA')
                        results['records']['AAAA'] = [str(r) for r in records]

                    elif record_type == 'MX':
                        records = self.dns_resolver.resolve(domain, 'MX')
                        results['records']['MX'] = [
                            {'priority': r.preference, 'server': str(r.exchange)}
                            for r in records
                        ]

                    elif record_type == 'NS':
                        records = self.dns_resolver.resolve(domain, 'NS')
                        results['records']['NS'] = [str(r) for r in records]

                    elif record_type == 'TXT':
                        records = self.dns_resolver.resolve(domain, 'TXT')
                        results['records']['TXT'] = [str(r).strip('"') for r in records]

                    elif record_type == 'SOA':
                        records = self.dns_resolver.resolve(domain, 'SOA')
                        soa = records[0]
                        results['records']['SOA'] = {
                            'mname': str(soa.mname),
                            'rname': str(soa.rname),
                            'serial': soa.serial,
                            'refresh': soa.refresh,
                            'retry': soa.retry,
                            'expire': soa.expire,
                            'minimum': soa.minimum
                        }

                    elif record_type == 'CNAME':
                        records = self.dns_resolver.resolve(domain, 'CNAME')
                        results['records']['CNAME'] = [str(r) for r in records]

                    elif record_type == 'CAA':
                        records = self.dns_resolver.resolve(domain, 'CAA')
                        results['records']['CAA'] = [str(r) for r in records]

                except dns.resolver.NoAnswer:
                    results['records'][record_type] = []
                except dns.resolver.NXDOMAIN:
                    return {'error': 'Domain does not exist', 'domain': domain}
                except Exception as e:
                    results['records'][record_type] = []

            # Summary statistics
            results['summary'] = {
                'total_record_types': len([v for v in results['records'].values() if v]),
                'has_ipv4': bool(results['records'].get('A')),
                'has_ipv6': bool(results['records'].get('AAAA')),
                'has_email': bool(results['records'].get('MX')),
                'nameserver_count': len(results['records'].get('NS', []))
            }

            print(f"✓ DNS lookup successful - found {results['summary']['total_record_types']} record types")
            return results

        except Exception as e:
            print(f"❌ DNS lookup failed: {e}")
            return {'error': f'DNS lookup failed: {str(e)}', 'domain': domain}

    def ip_lookup(self, ip_address):
        """
        Enhanced IP address lookup with geolocation
        """
        try:
            ip_address = ip_address.strip()
            print(f"🔍 Performing IP lookup for: {ip_address}")

            results = {
                'ip_address': ip_address,
                'query_time': datetime.utcnow().isoformat()
            }

            # Reverse DNS
            try:
                rev_name = dns.reversename.from_address(ip_address)
                rev_dns = self.dns_resolver.resolve(rev_name, 'PTR')
                results['reverse_dns'] = [str(r) for r in rev_dns]
            except:
                results['reverse_dns'] = []

            # Hostname
            try:
                hostname = socket.gethostbyaddr(ip_address)
                results['hostname'] = hostname[0]
                results['aliases'] = hostname[1]
            except:
                results['hostname'] = None
                results['aliases'] = []

            # IP classification
            results['classification'] = self._classify_ip(ip_address)

            # Basic geolocation using ip-api.com (free, no key needed)
            try:
                geo_response = requests.get(
                    f'http://ip-api.com/json/{ip_address}',
                    timeout=5,
                    headers={'User-Agent': self.user_agent}
                )
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data.get('status') == 'success':
                        results['geolocation'] = {
                            'country': geo_data.get('country'),
                            'country_code': geo_data.get('countryCode'),
                            'region': geo_data.get('regionName'),
                            'city': geo_data.get('city'),
                            'zip': geo_data.get('zip'),
                            'latitude': geo_data.get('lat'),
                            'longitude': geo_data.get('lon'),
                            'timezone': geo_data.get('timezone'),
                            'isp': geo_data.get('isp'),
                            'organization': geo_data.get('org'),
                            'as_number': geo_data.get('as')
                        }
            except:
                results['geolocation'] = None

            print(f"✓ IP lookup successful")
            return results

        except Exception as e:
            print(f"❌ IP lookup failed: {e}")
            return {'error': f'IP lookup failed: {str(e)}', 'ip_address': ip_address}

    def email_lookup(self, email):
        """
        Enhanced email intelligence
        """
        try:
            email = email.strip().lower()
            print(f"🔍 Performing email lookup for: {email}")

            results = {
                'email': email,
                'query_time': datetime.utcnow().isoformat()
            }

            # Validate syntax
            try:
                valid = validate_email(email, check_deliverability=False)
                results['is_valid_syntax'] = True
                results['normalized_email'] = valid.email
                results['local_part'] = valid.local_part
                results['domain'] = valid.domain
            except EmailNotValidError as e:
                results['is_valid_syntax'] = False
                results['validation_error'] = str(e)
                return results

            domain = results['domain']

            # MX records
            try:
                mx_records = self.dns_resolver.resolve(domain, 'MX')
                results['mx_records'] = [
                    {'priority': r.preference, 'server': str(r.exchange)}
                    for r in mx_records
                ]
                results['has_mx_records'] = True
            except:
                results['mx_records'] = []
                results['has_mx_records'] = False

            # SMTP verification (basic, non-intrusive)
            if results['has_mx_records']:
                results['smtp_responsive'] = self._test_smtp(str(results['mx_records'][0]['server']))

            # Disposable email detection
            results['is_disposable'] = self._is_disposable_email(domain)

            # Common email patterns
            results['patterns'] = self._analyze_email_pattern(email)

            # Domain info
            results['domain_info'] = self.whois_lookup(domain)

            print(f"✓ Email lookup successful")
            return results

        except Exception as e:
            print(f"❌ Email lookup failed: {e}")
            return {'error': f'Email lookup failed: {str(e)}', 'email': email}

    def url_analysis(self, url):
        """
        Enhanced URL intelligence and analysis
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            print(f"🔍 Analyzing URL: {url}")

            results = {
                'url': url,
                'query_time': datetime.utcnow().isoformat()
            }

            # Parse URL
            parsed = urlparse(url)
            results['parsed'] = {
                'scheme': parsed.scheme,
                'domain': parsed.netloc,
                'path': parsed.path,
                'params': parsed.params,
                'query': parsed.query,
                'fragment': parsed.fragment
            }

            # Fetch URL
            headers = {'User-Agent': self.user_agent}

            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True, verify=True)

            results['status_code'] = response.status_code
            results['final_url'] = response.url
            results['redirect_chain'] = [r.url for r in response.history] if response.history else []
            results['redirect_count'] = len(results['redirect_chain'])

            # Response headers
            results['headers'] = dict(response.headers)
            results['content_type'] = response.headers.get('Content-Type', 'unknown')
            results['content_length'] = response.headers.get('Content-Length', 'unknown')
            results['server'] = response.headers.get('Server', 'unknown')

            # Security headers analysis
            results['security_headers'] = {
                'x-frame-options': response.headers.get('X-Frame-Options'),
                'x-content-type-options': response.headers.get('X-Content-Type-Options'),
                'strict-transport-security': response.headers.get('Strict-Transport-Security'),
                'content-security-policy': response.headers.get('Content-Security-Policy'),
                'x-xss-protection': response.headers.get('X-XSS-Protection')
            }

            # HTML analysis
            if 'text/html' in results['content_type']:
                soup = BeautifulSoup(response.content, 'html.parser')

                # Title
                title = soup.find('title')
                results['title'] = title.string if title else None

                # Meta tags
                meta_tags = {}
                for meta in soup.find_all('meta'):
                    name = meta.get('name') or meta.get('property')
                    content = meta.get('content')
                    if name and content:
                        meta_tags[name] = content
                results['meta_tags'] = meta_tags

                # Links analysis
                links = soup.find_all('a', href=True)
                results['link_count'] = len(links)
                results['external_links'] = len([l for l in links if urlparse(l['href']).netloc and urlparse(l['href']).netloc != parsed.netloc])

                # Forms
                forms = soup.find_all('form')
                results['form_count'] = len(forms)

                # Scripts
                scripts = soup.find_all('script', src=True)
                results['script_count'] = len(scripts)

                # Technology fingerprinting
                tech = []

                if 'Server' in results['headers']:
                    tech.append({'category': 'Server', 'name': results['headers']['Server']})

                if 'X-Powered-By' in results['headers']:
                    tech.append({'category': 'Backend', 'name': results['headers']['X-Powered-By']})

                # CMS detection
                if soup.find('meta', {'name': 'generator', 'content': re.compile('WordPress', re.I)}):
                    tech.append({'category': 'CMS', 'name': 'WordPress'})
                elif soup.find('meta', {'name': 'generator', 'content': re.compile('Drupal', re.I)}):
                    tech.append({'category': 'CMS', 'name': 'Drupal'})
                elif soup.find('meta', {'name': 'generator', 'content': re.compile('Joomla', re.I)}):
                    tech.append({'category': 'CMS', 'name': 'Joomla'})

                # JavaScript frameworks
                if soup.find('script', src=re.compile('jquery', re.I)):
                    tech.append({'category': 'JavaScript', 'name': 'jQuery'})
                if soup.find('script', src=re.compile('react', re.I)):
                    tech.append({'category': 'JavaScript', 'name': 'React'})
                if soup.find('script', src=re.compile('vue', re.I)):
                    tech.append({'category': 'JavaScript', 'name': 'Vue.js'})
                if soup.find('script', src=re.compile('angular', re.I)):
                    tech.append({'category': 'JavaScript', 'name': 'Angular'})

                results['technologies'] = tech

            # SSL/TLS analysis
            if parsed.scheme == 'https':
                results['uses_ssl'] = True
                # Could add more SSL analysis here
            else:
                results['uses_ssl'] = False

            print(f"✓ URL analysis successful")
            return results

        except requests.exceptions.SSLError as e:
            return {'error': f'SSL certificate error: {str(e)}', 'url': url}
        except requests.exceptions.Timeout:
            return {'error': 'Request timeout - server did not respond', 'url': url}
        except requests.exceptions.ConnectionError:
            return {'error': 'Connection error - could not reach server', 'url': url}
        except Exception as e:
            print(f"❌ URL analysis failed: {e}")
            return {'error': f'URL analysis failed: {str(e)}', 'url': url}

    def file_hash_lookup(self, file_hash):
        """
        Enhanced file hash intelligence
        """
        try:
            file_hash = file_hash.strip().lower()
            print(f"🔍 Analyzing file hash: {file_hash}")

            results = {
                'hash': file_hash,
                'query_time': datetime.utcnow().isoformat()
            }

            # Determine hash type
            hash_length = len(file_hash)
            if hash_length == 32:
                results['hash_type'] = 'MD5'
            elif hash_length == 40:
                results['hash_type'] = 'SHA1'
            elif hash_length == 64:
                results['hash_type'] = 'SHA256'
            elif hash_length == 128:
                results['hash_type'] = 'SHA512'
            else:
                results['hash_type'] = 'Unknown'

            # Try to search on VirusTotal (using their free public API - requires API key)
            # Note: This is commented out as it requires API key
            # results['virustotal'] = self._check_virustotal(file_hash)

            results['note'] = 'File hash recorded. For threat intelligence, integrate VirusTotal API.'
            results['recommendations'] = [
                'Search this hash on VirusTotal.com manually',
                'Check against your internal threat database',
                'Search on Hybrid Analysis',
                'Check on MalwareBazaar'
            ]

            print(f"✓ File hash lookup successful")
            return results

        except Exception as e:
            print(f"❌ File hash lookup failed: {e}")
            return {'error': f'File hash lookup failed: {str(e)}'}

    def username_lookup(self, username):
        """
        Enhanced username enumeration (passive only)
        """
        try:
            username = username.strip()
            print(f"🔍 Searching for username: {username}")

            results = {
                'username': username,
                'query_time': datetime.utcnow().isoformat(),
                'platforms': []
            }

            # Platform definitions (passive check only)
            platforms = [
                {
                    'name': 'GitHub',
                    'url': f'https://github.com/{username}',
                    'check_string': 'github.com'
                },
                {
                    'name': 'Twitter',
                    'url': f'https://twitter.com/{username}',
                    'check_string': 'twitter.com'
                },
                {
                    'name': 'Reddit',
                    'url': f'https://reddit.com/user/{username}',
                    'check_string': 'reddit.com'
                },
                {
                    'name': 'Instagram',
                    'url': f'https://instagram.com/{username}',
                    'check_string': 'instagram.com'
                },
                {
                    'name': 'LinkedIn',
                    'url': f'https://linkedin.com/in/{username}',
                    'check_string': 'linkedin.com'
                }
            ]

            headers = {'User-Agent': self.user_agent}

            for platform in platforms:
                try:
                    response = requests.head(platform['url'], headers=headers, timeout=5, allow_redirects=True)
                    exists = response.status_code == 200

                    results['platforms'].append({
                        'name': platform['name'],
                        'url': platform['url'],
                        'possibly_exists': exists,
                        'status_code': response.status_code,
                        'note': 'Verified' if exists else 'Not found or private'
                    })

                    time.sleep(0.5)  # Rate limiting

                except:
                    results['platforms'].append({
                        'name': platform['name'],
                        'url': platform['url'],
                        'possibly_exists': None,
                        'error': 'Check failed'
                    })

            results['found_count'] = len([p for p in results['platforms'] if p.get('possibly_exists')])

            print(f"✓ Username search complete - found on {results['found_count']} platforms")
            return results

        except Exception as e:
            print(f"❌ Username lookup failed: {e}")
            return {'error': f'Username lookup failed: {str(e)}', 'username': username}

    # Helper methods
    def _clean_domain(self, domain):
        """Clean and normalize domain name"""
        domain = domain.strip().lower()
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.replace('www.', '')
        domain = domain.split('/')[0]
        return domain

    def _safe_extract(self, value):
        """Safely extract value from whois result"""
        if isinstance(value, list):
            return value[0] if value else 'Not available'
        return value if value else 'Not available'

    def _format_date(self, date_value):
        """Format date from whois result"""
        try:
            if isinstance(date_value, list):
                date_value = date_value[0]
            if date_value:
                return str(date_value)
        except:
            pass
        return 'Not available'

    def _classify_ip(self, ip):
        """Classify IP address type"""
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return {'type': 'Unknown', 'is_private': None}

            first = int(octets[0])
            second = int(octets[1])

            if first == 10:
                return {'type': 'Private', 'range': '10.0.0.0/8', 'is_private': True}
            elif first == 172 and 16 <= second <= 31:
                return {'type': 'Private', 'range': '172.16.0.0/12', 'is_private': True}
            elif first == 192 and second == 168:
                return {'type': 'Private', 'range': '192.168.0.0/16', 'is_private': True}
            elif first == 127:
                return {'type': 'Loopback', 'range': '127.0.0.0/8', 'is_private': True}
            elif first == 169 and second == 254:
                return {'type': 'Link-Local', 'range': '169.254.0.0/16', 'is_private': True}
            else:
                return {'type': 'Public', 'is_private': False}
        except:
            return {'type': 'Unknown', 'is_private': None}

    def _test_smtp(self, mx_server):
        """Test SMTP server connectivity"""
        try:
            import smtplib
            server = smtplib.SMTP(timeout=5)
            server.connect(mx_server)
            server.quit()
            return True
        except:
            return False

    def _is_disposable_email(self, domain):
        """Check if email domain is disposable"""
        disposable_domains = [
            'tempmail.com', 'guerrillamail.com', '10minutemail.com',
            'throwaway.email', 'mailinator.com', 'trashmail.com',
            'maildrop.cc', 'yopmail.com', 'fake-mail.com'
        ]
        return domain.lower() in disposable_domains

    def _analyze_email_pattern(self, email):
        """Analyze email pattern"""
        local_part = email.split('@')[0]
        patterns = {
            'has_numbers': bool(re.search(r'\d', local_part)),
            'has_dots': '.' in local_part,
            'has_underscores': '_' in local_part,
            'has_hyphens': '-' in local_part,
            'length': len(local_part),
            'appears_generated': len(local_part) > 15 and bool(re.search(r'\d{3,}', local_part))
        }
        return patterns

# Instantiate enhanced tools
osint_tools = EnhancedOSINTTools()