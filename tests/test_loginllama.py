import unittest
from unittest.mock import patch, Mock
from loginllama.loginllama import LoginLlama, LoginCheckStatus

# Mock request object similar to Express' request
def mock_request(ip, user_agent):
    class MockRequest:
        META = {
            'HTTP_X_FORWARDED_FOR': ip,
            'REMOTE_ADDR': ip,
            'HTTP_USER_AGENT': user_agent
        }
        remote_addr = ip

    return MockRequest()

class TestLoginLlama(unittest.TestCase):
    def setUp(self):
        self.login_llama = LoginLlama(api_token='mockToken')

    @patch('loginllama.api.Api.post')
    def test_check_valid_login(self, mock_post):
        mock_post.return_value = {
            'status': 'success',
            'message': 'Valid login',
            'codes': ['login_valid']
        }
        result = self.login_llama.check_login(
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0',
            identity_key='validUser'
        )

        self.assertEqual(result.status, 'success')
        self.assertEqual(result.message, 'Valid login')
        self.assertIn(LoginCheckStatus.VALID, result.codes)

    @patch('loginllama.api.Api.post')
    def test_check_invalid_login(self, mock_post):
        mock_post.side_effect = Exception('Login check failed')

        with self.assertRaises(Exception) as context:
            self.login_llama.check_login(
                ip_address='192.168.1.1',
                user_agent='Mozilla/5.0',
                identity_key='invalidUser'
            )

        self.assertEqual(str(context.exception), 'Login check failed')

    def test_missing_ip_address(self):
        with self.assertRaises(ValueError) as context:
            self.login_llama.check_login(
                user_agent='Mozilla/5.0',
                identity_key='validUser'
            )

        self.assertEqual(str(context.exception), 'ip_address is required')

    def test_missing_user_agent(self):
        with self.assertRaises(ValueError) as context:
            self.login_llama.check_login(
                ip_address='192.168.1.1',
                identity_key='validUser'
            )

        self.assertEqual(str(context.exception), 'user_agent is required')

    def test_missing_identity_key(self):
        with self.assertRaises(ValueError) as context:
            self.login_llama.check_login(
                ip_address='192.168.1.1',
                user_agent='Mozilla/5.0',
                identity_key=None
            )

        self.assertEqual(str(context.exception), 'identity_key is required')

    @patch('loginllama.api.Api.post')
    def test_extract_ip_address_and_user_agent_from_request(self, mock_post):
        mock_post.return_value = {
            'status': 'success',
            'message': 'Valid login',
            'codes': ['login_valid']
        }

        req = mock_request('192.168.1.1', 'Mozilla/5.0')
        result = self.login_llama.check_login(
            request=req,
            identity_key='validUser'
        )

        self.assertEqual(result.status, 'success')
        self.assertEqual(result.message, 'Valid login')
        self.assertIn(LoginCheckStatus.VALID, result.codes)

if __name__ == '__main__':
    unittest.main()
