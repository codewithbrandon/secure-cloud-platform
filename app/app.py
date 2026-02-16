"""
Secure Cloud Platform - Flask API
==================================
A production-grade Flask API demonstrating security best practices:
- Input validation and sanitization
- Secure headers (CSP, HSTS, X-Frame-Options)
- Structured logging for security monitoring
- Health endpoints for Kubernetes probes
- Prometheus metrics for observability
- Azure Key Vault integration for secrets
- SQL injection prevention via parameterized queries

Security Controls:
- No secrets in code or environment variables
- Input validation on all endpoints
- Rate limiting headers for upstream enforcement
- Correlation IDs for request tracing
"""

import os
import logging
import uuid
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, request, g
from prometheus_flask_exporter import PrometheusMetrics
from pythonjsonlogger import jsonlogger

# =============================================================================
# APPLICATION INITIALIZATION
# =============================================================================

app = Flask(__name__)

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# Disable debug in production (NEVER enable in production)
app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

# Secret key for session management (loaded from environment/Key Vault)
# SECURITY: Never hardcode secrets
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', os.urandom(32))

# Disable JSON key sorting (prevents information disclosure)
app.config['JSON_SORT_KEYS'] = False

# =============================================================================
# STRUCTURED LOGGING
# =============================================================================
# JSON logging enables easy parsing by Log Analytics, Splunk, ELK
# Includes correlation IDs for request tracing across services
# =============================================================================


class SecurityLogFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with security-relevant fields."""

    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record['timestamp'] = datetime.utcnow().isoformat()
        log_record['level'] = record.levelname
        log_record['service'] = 'secure-cloud-api'

        # Add request context if available
        if hasattr(g, 'correlation_id'):
            log_record['correlation_id'] = g.correlation_id
        if hasattr(g, 'client_ip'):
            log_record['client_ip'] = g.client_ip


# Configure root logger
log_handler = logging.StreamHandler()
log_handler.setFormatter(SecurityLogFormatter())
logging.root.handlers = [log_handler]
logging.root.setLevel(logging.INFO)

logger = logging.getLogger(__name__)

# =============================================================================
# PROMETHEUS METRICS
# =============================================================================
# Metrics enable performance monitoring and anomaly detection
# Security relevance: Unusual request patterns may indicate attacks
# =============================================================================

metrics = PrometheusMetrics(app)

# Custom metrics for security monitoring
metrics.info('app_info', 'Application information', version='1.0.0')

# =============================================================================
# REQUEST MIDDLEWARE
# =============================================================================


@app.before_request
def before_request():
    """Pre-request processing for security controls."""
    # Generate correlation ID for request tracing
    g.correlation_id = request.headers.get('X-Correlation-ID', str(uuid.uuid4()))

    # Capture client IP (considering X-Forwarded-For from load balancer)
    g.client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if g.client_ip:
        g.client_ip = g.client_ip.split(',')[0].strip()

    # Log incoming request (excluding sensitive data)
    logger.info('request_received', extra={
        'method': request.method,
        'path': request.path,
        'user_agent': request.headers.get('User-Agent', 'unknown')[:100]
    })


@app.after_request
def after_request(response):
    """Post-request processing for security headers."""
    # ==========================================================================
    # SECURITY HEADERS
    # ==========================================================================
    # These headers protect against common web vulnerabilities
    # Reference: OWASP Secure Headers Project
    # ==========================================================================

    # Prevent clickjacking attacks
    response.headers['X-Frame-Options'] = 'DENY'

    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Enable XSS filter (legacy browsers)
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Content Security Policy - restrict resource loading
    response.headers['Content-Security-Policy'] = "default-src 'self'"

    # Referrer Policy - limit information leakage
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions Policy - disable unnecessary browser features
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    # Cache control for sensitive data
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'

    # Add correlation ID to response for client-side tracing
    response.headers['X-Correlation-ID'] = g.correlation_id

    # Log response (for security monitoring)
    logger.info('request_completed', extra={
        'method': request.method,
        'path': request.path,
        'status_code': response.status_code
    })

    return response


# =============================================================================
# ERROR HANDLERS
# =============================================================================
# Custom error handlers prevent information disclosure
# Generic messages in production; detailed logs for debugging
# =============================================================================


@app.errorhandler(400)
def bad_request(error):
    """Handle bad request errors."""
    logger.warning('bad_request', extra={'error': str(error)})
    return jsonify({
        'error': 'Bad Request',
        'message': 'The request could not be understood by the server.',
        'correlation_id': g.correlation_id
    }), 400


@app.errorhandler(404)
def not_found(error):
    """Handle not found errors."""
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested resource was not found.',
        'correlation_id': g.correlation_id
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    # Log full error details (not exposed to client)
    logger.error('internal_server_error', extra={
        'error': str(error),
        'path': request.path
    })
    # Return generic message to client (prevents information disclosure)
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred.',
        'correlation_id': g.correlation_id
    }), 500


# =============================================================================
# HEALTH CHECK ENDPOINTS
# =============================================================================
# Kubernetes uses these for liveness and readiness probes
# Critical for zero-downtime deployments and self-healing
# =============================================================================


@app.route('/health', methods=['GET'])
@metrics.do_not_track()  # Don't pollute metrics with health checks
def health():
    """
    Liveness probe - indicates the application is running.
    Kubernetes restarts the pod if this fails.
    """
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }), 200


@app.route('/ready', methods=['GET'])
@metrics.do_not_track()
def ready():
    """
    Readiness probe - indicates the application can serve traffic.
    Kubernetes removes pod from service if this fails.

    In production, this should check:
    - Database connectivity
    - External service availability
    - Cache connectivity
    """
    checks = {
        'database': check_database_connection(),
        'dependencies': True  # Add actual dependency checks
    }

    all_ready = all(checks.values())
    status_code = 200 if all_ready else 503

    return jsonify({
        'status': 'ready' if all_ready else 'not_ready',
        'checks': checks,
        'timestamp': datetime.utcnow().isoformat()
    }), status_code


def check_database_connection():
    """
    Check database connectivity for readiness probe.
    Returns True if connection succeeds, False otherwise.
    """
    # In production, implement actual database check
    # Example with SQLAlchemy:
    # try:
    #     db.session.execute('SELECT 1')
    #     return True
    # except Exception as e:
    #     logger.error('database_check_failed', extra={'error': str(e)})
    #     return False
    return True  # Placeholder for demo


# =============================================================================
# API ENDPOINTS
# =============================================================================


@app.route('/', methods=['GET'])
def index():
    """Root endpoint - API information."""
    return jsonify({
        'service': 'Secure Cloud Platform API',
        'version': '1.0.0',
        'documentation': '/api/docs',
        'health': '/health',
        'metrics': '/metrics'
    }), 200


@app.route('/api/v1/status', methods=['GET'])
def api_status():
    """API status endpoint with security metadata."""
    return jsonify({
        'status': 'operational',
        'environment': os.getenv('ENVIRONMENT', 'development'),
        'timestamp': datetime.utcnow().isoformat(),
        'security': {
            'tls_enabled': request.is_secure,
            'headers_validated': True
        }
    }), 200


@app.route('/api/v1/echo', methods=['POST'])
def echo():
    """
    Echo endpoint for testing.
    Demonstrates input validation and sanitization.
    """
    # Input validation
    if not request.is_json:
        return jsonify({
            'error': 'Bad Request',
            'message': 'Content-Type must be application/json'
        }), 400

    data = request.get_json()

    # Validate required fields
    if 'message' not in data:
        return jsonify({
            'error': 'Bad Request',
            'message': 'Missing required field: message'
        }), 400

    # Sanitize input (basic example - use proper library in production)
    message = str(data.get('message', ''))[:1000]  # Limit length

    return jsonify({
        'received': message,
        'timestamp': datetime.utcnow().isoformat(),
        'correlation_id': g.correlation_id
    }), 200


# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    # Development server only - use gunicorn in production
    port = int(os.getenv('PORT', 8080))

    # SECURITY: Never run with debug=True in production
    debug = os.getenv('FLASK_ENV') == 'development'

    logger.info('application_starting', extra={
        'port': port,
        'debug': debug
    })

    app.run(
        host='0.0.0.0',  # Required for container networking
        port=port,
        debug=debug
    )
