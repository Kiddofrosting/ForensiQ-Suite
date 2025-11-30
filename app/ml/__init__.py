"""
Machine Learning module initialization
"""

# Import the detector instance
from app.ml.anomaly_detector import anomaly_detector

# Import routes
from app.ml import routes

# Export for easy access
__all__ = ['anomaly_detector', 'routes']