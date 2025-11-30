"""
Unit tests for ForensIQ Suite backend
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest
from datetime import datetime
from app import create_app, get_db
from app.models import User, Case, Evidence, AuditLog
from app.utils import (
    compute_file_hash, generate_case_number, generate_otp,
    validate_password_strength, format_file_size
)


class TestModels(unittest.TestCase):
    """Test database models"""

    def test_user_model(self):
        """Test User model"""
        user = User(
            username='testuser',
            email='test@example.com',
            password='Test@123',
            role='investigator'
        )

        user_dict = user.to_dict()

        self.assertEqual(user_dict['username'], 'testuser')
        self.assertEqual(user_dict['role'], 'investigator')
        self.assertTrue('password_hash' in user_dict)
        self.assertNotEqual(user_dict['password_hash'], 'Test@123')

    def test_password_verification(self):
        """Test password hashing and verification"""
        user = User(
            username='testuser',
            email='test@example.com',
            password='Test@123',
            role='investigator'
        )

        # Correct password
        self.assertTrue(User.verify_password(user.password_hash, 'Test@123'))

        # Incorrect password
        self.assertFalse(User.verify_password(user.password_hash, 'WrongPassword'))

    def test_case_model(self):
        """Test Case model"""
        case = Case(
            case_number='CASE-20220801-ABC123',
            title='Test Case',
            description='Test description',
            created_by='user_id_123'
        )

        case_dict = case.to_dict()

        self.assertEqual(case_dict['case_number'], 'CASE-20220801-ABC123')
        self.assertEqual(case_dict['status'], 'open')
        self.assertIsInstance(case_dict['created_at'], datetime)

    def test_audit_log_hash_chain(self):
        """Test audit log hash chain"""
        log1 = AuditLog(
            user_id='user1',
            username='testuser',
            role='admin',
            action='login',
            ip_address='192.168.1.1'
        )

        log2 = AuditLog(
            user_id='user1',
            username='testuser',
            role='admin',
            action='logout',
            ip_address='192.168.1.1',
            previous_hash=log1.current_hash
        )

        # Verify hashes are different
        self.assertNotEqual(log1.current_hash, log2.current_hash)

        # Verify chain link
        self.assertEqual(log2.previous_hash, log1.current_hash)

    def test_audit_log_chain_verification(self):
        """Test audit log chain verification"""
        logs = []
        previous_hash = '0' * 64

        for i in range(5):
            log = AuditLog(
                user_id=f'user{i}',
                username=f'user{i}',
                role='admin',
                action='login',
                ip_address='192.168.1.1',
                previous_hash=previous_hash
            )
            logs.append(log.to_dict())
            previous_hash = log.current_hash

        # Verify intact chain
        is_valid, message = AuditLog.verify_chain(logs)
        self.assertTrue(is_valid)

        # Break the chain
        logs[2]['previous_hash'] = 'tampered_hash'
        is_valid, message = AuditLog.verify_chain(logs)
        self.assertFalse(is_valid)


class TestUtils(unittest.TestCase):
    """Test utility functions"""

    def test_password_strength_validation(self):
        """Test password strength validator"""
        # Weak passwords
        weak_passwords = [
            'short',
            'nouppercase123!',
            'NOLOWERCASE123!',
            'NoDigits!',
            'NoSpecial123'
        ]

        for password in weak_passwords:
            is_strong, message = validate_password_strength(password)
            self.assertFalse(is_strong)

        # Strong password
        is_strong, message = validate_password_strength('Strong@Pass123')
        self.assertTrue(is_strong)

    def test_case_number_generation(self):
        """Test case number generation"""
        case_number = generate_case_number()

        self.assertTrue(case_number.startswith('CASE-'))
        self.assertGreater(len(case_number), 15)

    def test_otp_generation(self):
        """Test OTP generation"""
        otp = generate_otp(6)

        self.assertEqual(len(otp), 6)
        self.assertTrue(otp.isdigit())

    def test_file_size_formatting(self):
        """Test file size formatting"""
        self.assertEqual(format_file_size(500), '500.00 B')
        self.assertEqual(format_file_size(1024), '1.00 KB')
        self.assertEqual(format_file_size(1048576), '1.00 MB')
        self.assertEqual(format_file_size(1073741824), '1.00 GB')


class TestOSINT(unittest.TestCase):
    """Test OSINT tools"""

    def test_email_validation(self):
        """Test email validation"""
        from app.osint.osint_tools import osint_tools

        # Valid email
        result = osint_tools.email_lookup('test@example.com')
        self.assertIn('is_valid_syntax', result)

        # Invalid email
        result = osint_tools.email_lookup('invalid-email')
        self.assertFalse(result.get('is_valid_syntax', True))

    def test_ip_lookup(self):
        """Test IP lookup"""
        from app.osint.osint_tools import osint_tools

        # Private IP
        result = osint_tools.ip_lookup('192.168.1.1')
        self.assertTrue(result.get('is_private', False))

        # Public IP
        result = osint_tools.ip_lookup('8.8.8.8')
        self.assertFalse(result.get('is_private', True))


class TestEncryption(unittest.TestCase):
    """Test encryption and hashing"""

    def setUp(self):
        """Set up test file"""
        self.test_file = 'test_file.txt'
        with open(self.test_file, 'w') as f:
            f.write('Test content for encryption')

    def tearDown(self):
        """Clean up test files"""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

        encrypted_file = self.test_file + '.encrypted'
        if os.path.exists(encrypted_file):
            os.remove(encrypted_file)

    def test_file_hashing(self):
        """Test file hash computation"""
        sha256 = compute_file_hash(self.test_file, 'sha256')
        md5 = compute_file_hash(self.test_file, 'md5')

        self.assertEqual(len(sha256), 64)
        self.assertEqual(len(md5), 32)

    def test_file_encryption(self):
        """Test file encryption and decryption"""
        from app.utils import encrypt_file, decrypt_file, generate_encryption_key

        # Generate key
        key = generate_encryption_key()

        # Encrypt
        encrypted_path = encrypt_file(self.test_file, key)
        self.assertTrue(os.path.exists(encrypted_path))

        # Decrypt
        decrypted_data = decrypt_file(encrypted_path, key)
        self.assertEqual(decrypted_data, b'Test content for encryption')


class TestAnomalyDetection(unittest.TestCase):
    """Test anomaly detection"""

    def test_feature_extraction(self):
        """Test user feature extraction"""
        from app.ml.anomaly_detector import anomaly_detector

        # This would require a populated database
        # For now, just test that the method exists
        self.assertTrue(hasattr(anomaly_detector, 'extract_user_features'))
        self.assertTrue(hasattr(anomaly_detector, 'detect_anomalies'))


def run_tests():
    """Run all tests"""
    print("=" * 70)
    print("  ForensIQ Suite - Backend Test Suite")
    print("=" * 70 + "\n")

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestModels))
    suite.addTests(loader.loadTestsFromTestCase(TestUtils))
    suite.addTests(loader.loadTestsFromTestCase(TestOSINT))
    suite.addTests(loader.loadTestsFromTestCase(TestEncryption))
    suite.addTests(loader.loadTestsFromTestCase(TestAnomalyDetection))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 70)
    print("  Test Summary")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)