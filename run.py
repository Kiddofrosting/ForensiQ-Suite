"""
ForensIQ Suite - Digital Evidence Management System
Main application entry point
"""

import os
from app import create_app

# Create Flask application
app = create_app(os.getenv('FLASK_ENV', 'development'))

if __name__ == '__main__':
    # Run the application
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )