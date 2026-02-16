"""
Secure Cloud Platform - API Tests
==================================
Unit and integration tests for the Flask API
"""

import pytest
from app import app


@pytest.fixture
def client():
    """Create test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_health_returns_200(self, client):
        """Health endpoint should return 200 OK."""
        response = client.get('/health')
        assert response.status_code == 200

    def test_health_returns_healthy_status(self, client):
        """Health endpoint should return healthy status."""
        response = client.get('/health')
        data = response.get_json()
        assert data['status'] == 'healthy'

    def test_ready_returns_200(self, client):
        """Ready endpoint should return 200 when ready."""
        response = client.get('/ready')
        assert response.status_code == 200

    def test_ready_returns_ready_status(self, client):
        """Ready endpoint should return ready status."""
        response = client.get('/ready')
        data = response.get_json()
        assert data['status'] == 'ready'


class TestAPIEndpoints:
    """Test API endpoints."""

    def test_index_returns_200(self, client):
        """Index endpoint should return 200 OK."""
        response = client.get('/')
        assert response.status_code == 200

    def test_index_returns_service_info(self, client):
        """Index endpoint should return service information."""
        response = client.get('/')
        data = response.get_json()
        assert 'service' in data
        assert 'version' in data

    def test_status_returns_200(self, client):
        """Status endpoint should return 200 OK."""
        response = client.get('/api/v1/status')
        assert response.status_code == 200

    def test_status_returns_operational(self, client):
        """Status endpoint should return operational status."""
        response = client.get('/api/v1/status')
        data = response.get_json()
        assert data['status'] == 'operational'


class TestEchoEndpoint:
    """Test echo endpoint input validation."""

    def test_echo_requires_json(self, client):
        """Echo endpoint should reject non-JSON requests."""
        response = client.post('/api/v1/echo', data='not json')
        assert response.status_code == 400

    def test_echo_requires_message_field(self, client):
        """Echo endpoint should require message field."""
        response = client.post(
            '/api/v1/echo',
            json={'other': 'data'},
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_echo_returns_message(self, client):
        """Echo endpoint should return the message."""
        response = client.post(
            '/api/v1/echo',
            json={'message': 'test message'},
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['received'] == 'test message'


class TestSecurityHeaders:
    """Test security headers are present."""

    def test_x_frame_options_header(self, client):
        """X-Frame-Options header should be DENY."""
        response = client.get('/health')
        assert response.headers.get('X-Frame-Options') == 'DENY'

    def test_x_content_type_options_header(self, client):
        """X-Content-Type-Options header should be nosniff."""
        response = client.get('/health')
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'

    def test_content_security_policy_header(self, client):
        """Content-Security-Policy header should be present."""
        response = client.get('/health')
        assert 'Content-Security-Policy' in response.headers

    def test_correlation_id_header(self, client):
        """X-Correlation-ID header should be present."""
        response = client.get('/health')
        assert 'X-Correlation-ID' in response.headers


class TestErrorHandling:
    """Test error handling."""

    def test_404_returns_json(self, client):
        """404 errors should return JSON."""
        response = client.get('/nonexistent')
        assert response.status_code == 404
        data = response.get_json()
        assert 'error' in data

    def test_404_includes_correlation_id(self, client):
        """404 errors should include correlation ID."""
        response = client.get('/nonexistent')
        data = response.get_json()
        assert 'correlation_id' in data
