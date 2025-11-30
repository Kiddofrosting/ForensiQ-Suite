"""
Enhanced Anomaly Detection Engine with Robust Error Handling
Fixed issues: data validation, error handling, model persistence
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from pyod.models.iforest import IForest
from pyod.models.lof import LOF
from pyod.models.knn import KNN
from pyod.models.hbos import HBOS
from sklearn.preprocessing import RobustScaler
from collections import Counter, defaultdict
import pickle
import os
from app import get_db
from app.models import AnomalyAlert
from bson import ObjectId
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EnhancedAnomalyDetector:
    """
    Production-ready ML-based anomaly detection with:
    - Robust error handling
    - Data validation
    - Model persistence
    - Configurable thresholds
    """

    def __init__(self, model_path='data/models'):
        """Initialize detector with configurable parameters"""
        self.model_path = model_path
        os.makedirs(model_path, exist_ok=True)

        # Multiple models for ensemble detection
        self.models = {
            'isolation_forest': IForest(contamination=0.1, random_state=42),
            'lof': LOF(contamination=0.1, n_neighbors=20),
            'knn': KNN(contamination=0.1, n_neighbors=5),
            'hbos': HBOS(contamination=0.1)
        }

        self.scaler = RobustScaler()
        self.feature_names = []
        self.is_fitted = False

        # Configuration
        self.config = {
            'min_samples': 5,
            'min_users_for_detection': 3,
            'min_features': 10,
            'default_threshold': 0.65,
            'critical_threshold': 0.9
        }

    def validate_data(self, data, min_samples=5):
        """
        Validate input data before processing

        Args:
            data: Input data to validate
            min_samples: Minimum number of samples required

        Returns:
            tuple: (is_valid, error_message)
        """
        if data is None or len(data) == 0:
            return False, "No data provided"

        if len(data) < min_samples:
            return False, f"Insufficient data: {len(data)} samples (minimum: {min_samples})"

        return True, None

    def safe_calculate_mean(self, values):
        """Safely calculate mean with fallback"""
        try:
            if not values or len(values) == 0:
                return 0.0
            return float(np.mean(values))
        except Exception as e:
            logger.warning(f"Error calculating mean: {e}")
            return 0.0

    def safe_calculate_std(self, values):
        """Safely calculate standard deviation with fallback"""
        try:
            if not values or len(values) < 2:
                return 0.0
            return float(np.std(values))
        except Exception as e:
            logger.warning(f"Error calculating std: {e}")
            return 0.0

    def parse_timestamp(self, timestamp):
        """Safely parse timestamp from various formats"""
        try:
            if isinstance(timestamp, datetime):
                return timestamp
            if isinstance(timestamp, str):
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return None
        except Exception as e:
            logger.warning(f"Error parsing timestamp: {e}")
            return None

    def extract_enhanced_features(self, user_id, lookback_days=14):
        """
        Extract comprehensive behavioral features with robust error handling

        Args:
            user_id: User ID to extract features for
            lookback_days: Number of days to look back

        Returns:
            dict: Feature dictionary or None if insufficient data
        """
        try:
            db = get_db()
            start_date = datetime.utcnow() - timedelta(days=lookback_days)

            # Get all logs for user with error handling
            try:
                logs = list(db.audit_logs.find({
                    'user_id': user_id,
                    'timestamp': {'$gte': start_date}
                }).sort('timestamp', 1))
            except Exception as e:
                logger.error(f"Database error fetching logs for user {user_id}: {e}")
                return None

            # Validate data
            is_valid, error_msg = self.validate_data(logs, self.config['min_samples'])
            if not is_valid:
                logger.info(f"Insufficient data for user {user_id}: {error_msg}")
                return None

            features = {}

            # === LOGIN FEATURES ===
            login_logs = [l for l in logs if l.get('action') in ['login', 'failed_login']]

            features['login_count'] = len([l for l in login_logs if l.get('action') == 'login'])
            features['failed_login_count'] = len([l for l in login_logs if l.get('action') == 'failed_login'])
            features['login_success_rate'] = (
                features['login_count'] / max(len(login_logs), 1)
            )

            # Login time patterns with safe parsing
            login_hours = []
            for log in login_logs:
                if log.get('action') == 'login':
                    ts = self.parse_timestamp(log.get('timestamp'))
                    if ts:
                        login_hours.append(ts.hour)

            if login_hours:
                features['avg_login_hour'] = self.safe_calculate_mean(login_hours)
                features['std_login_hour'] = self.safe_calculate_std(login_hours)
                features['night_logins'] = sum(1 for h in login_hours if h >= 22 or h <= 5)
                features['business_hours_logins'] = sum(1 for h in login_hours if 9 <= h <= 17)
                features['weekend_logins'] = 0
            else:
                features['avg_login_hour'] = 12.0
                features['std_login_hour'] = 0.0
                features['night_logins'] = 0
                features['business_hours_logins'] = 0
                features['weekend_logins'] = 0

            # === IP ADDRESS FEATURES ===
            ip_addresses = [l.get('ip_address') for l in logs if l.get('ip_address')]
            unique_ips = set(ip_addresses)
            features['unique_ip_count'] = len(unique_ips)

            if ip_addresses:
                ip_counter = Counter(ip_addresses)
                most_common_ip_freq = ip_counter.most_common(1)[0][1] if ip_counter else 0
                features['ip_concentration'] = most_common_ip_freq / len(ip_addresses)
            else:
                features['ip_concentration'] = 0.0

            # === EVIDENCE ACCESS FEATURES ===
            evidence_logs = [l for l in logs if 'evidence' in l.get('action', '').lower()]
            features['evidence_view_count'] = sum(1 for l in evidence_logs if 'viewed' in l.get('action', ''))
            features['evidence_download_count'] = sum(1 for l in evidence_logs if 'downloaded' in l.get('action', ''))
            features['evidence_upload_count'] = sum(1 for l in evidence_logs if 'uploaded' in l.get('action', ''))
            features['evidence_delete_count'] = sum(1 for l in evidence_logs if 'deleted' in l.get('action', ''))

            # Download to view ratio with safe division
            if features['evidence_view_count'] > 0:
                features['download_to_view_ratio'] = (
                    features['evidence_download_count'] / features['evidence_view_count']
                )
            else:
                features['download_to_view_ratio'] = 0.0

            # === CASE ACCESS FEATURES ===
            case_logs = [l for l in logs if 'case' in l.get('action', '').lower()]
            features['case_interaction_count'] = len(case_logs)
            features['case_create_count'] = sum(1 for l in case_logs if 'created' in l.get('action', ''))
            features['case_update_count'] = sum(1 for l in case_logs if 'updated' in l.get('action', ''))
            features['case_view_count'] = sum(1 for l in case_logs if 'viewed' in l.get('action', ''))

            # === OSINT FEATURES ===
            osint_logs = [l for l in logs if 'osint' in l.get('action', '').lower()]
            features['osint_query_count'] = len(osint_logs)
            features['osint_per_day'] = features['osint_query_count'] / lookback_days

            # === ACTIVITY BURST DETECTION ===
            if len(logs) >= 10:
                timestamps = []
                for log in logs:
                    ts = self.parse_timestamp(log.get('timestamp'))
                    if ts:
                        timestamps.append(ts)

                if len(timestamps) > 1:
                    timestamps.sort()
                    time_diffs = [
                        (timestamps[i+1] - timestamps[i]).total_seconds()
                        for i in range(len(timestamps)-1)
                    ]

                    features['avg_action_interval'] = self.safe_calculate_mean(time_diffs)
                    features['min_action_interval'] = min(time_diffs) if time_diffs else 0
                    features['actions_under_1s'] = sum(1 for d in time_diffs if d < 1)
                    features['actions_under_5s'] = sum(1 for d in time_diffs if d < 5)
                    features['burst_score'] = (
                        features['actions_under_5s'] / len(time_diffs) if time_diffs else 0
                    )
                else:
                    features.update({
                        'avg_action_interval': 0.0,
                        'min_action_interval': 0.0,
                        'actions_under_1s': 0,
                        'actions_under_5s': 0,
                        'burst_score': 0.0
                    })
            else:
                features.update({
                    'avg_action_interval': 0.0,
                    'min_action_interval': 0.0,
                    'actions_under_1s': 0,
                    'actions_under_5s': 0,
                    'burst_score': 0.0
                })

            # === SESSION FEATURES ===
            features['total_actions'] = len(logs)
            features['actions_per_day'] = features['total_actions'] / lookback_days

            action_types = set([l.get('action', '') for l in logs])
            features['unique_action_types'] = len(action_types)

            # === SUSPICIOUS BEHAVIOR INDICATORS ===
            features['failed_login_spike'] = 1 if features['failed_login_count'] > 5 else 0
            features['night_activity_ratio'] = (
                features['night_logins'] / max(features['login_count'], 1)
            )
            features['evidence_access_spike'] = 1 if features['evidence_view_count'] > 50 else 0
            features['osint_abuse'] = 1 if features['osint_query_count'] > 100 else 0
            features['rapid_ip_switching'] = 1 if features['unique_ip_count'] > 10 else 0
            features['has_activity_burst'] = 1 if features['burst_score'] > 0.3 else 0

            # === NORMALIZED FEATURES ===
            features['normalized_login_freq'] = features['login_count'] / lookback_days
            features['normalized_evidence_access'] = features['evidence_view_count'] / lookback_days
            features['normalized_osint_rate'] = features['osint_query_count'] / lookback_days

            return features

        except Exception as e:
            logger.error(f"Error extracting features for user {user_id}: {e}", exc_info=True)
            return None

    def detect_anomalies(self, lookback_days=14, threshold=None):
        """
        Run comprehensive anomaly detection with robust error handling

        Args:
            lookback_days: Days of history to analyze
            threshold: Detection threshold (None = use default)

        Returns:
            dict: Detection results with metadata
        """
        if threshold is None:
            threshold = self.config['default_threshold']

        try:
            db = get_db()
            logger.info("🔍 Starting enhanced anomaly detection...")

            # Get all active users
            users = list(db.users.find({'status': 'active'}))

            if len(users) < self.config['min_users_for_detection']:
                return {
                    'anomalies_detected': 0,
                    'message': f'Need at least {self.config["min_users_for_detection"]} active users',
                    'details': {},
                    'success': False
                }

            # Extract features for all users
            user_features_list = []
            user_ids = []
            user_data = {}

            for user in users:
                user_id = str(user['_id'])
                features = self.extract_enhanced_features(user_id, lookback_days)

                if features and len(features) >= self.config['min_features']:
                    user_features_list.append(features)
                    user_ids.append(user_id)
                    user_data[user_id] = {
                        'username': user['username'],
                        'role': user['role']
                    }

            if len(user_features_list) < self.config['min_users_for_detection']:
                return {
                    'anomalies_detected': 0,
                    'message': 'Not enough user activity for detection',
                    'details': {},
                    'success': False
                }

            logger.info(f"✅ Extracted features for {len(user_features_list)} users")

            # Convert to DataFrame with error handling
            try:
                df = pd.DataFrame(user_features_list)
                self.feature_names = list(df.columns)
                df.fillna(0, inplace=True)

                # Validate DataFrame
                if df.empty or df.shape[0] < 3:
                    raise ValueError("Insufficient data in DataFrame")

            except Exception as e:
                logger.error(f"Error creating DataFrame: {e}")
                return {
                    'anomalies_detected': 0,
                    'message': f'Data processing error: {str(e)}',
                    'details': {},
                    'success': False
                }

            # Scale features with error handling
            try:
                X = self.scaler.fit_transform(df)
            except Exception as e:
                logger.error(f"Error scaling features: {e}")
                return {
                    'anomalies_detected': 0,
                    'message': f'Feature scaling error: {str(e)}',
                    'details': {},
                    'success': False
                }

            logger.info("🤖 Running ensemble detection...")

            # Run multiple models with error handling
            all_scores = {}
            all_labels = {}

            for model_name, model in self.models.items():
                try:
                    model.fit(X)
                    scores = model.decision_scores_
                    labels = model.labels_

                    # Normalize scores
                    if scores.max() > scores.min():
                        normalized_scores = (scores - scores.min()) / (scores.max() - scores.min())
                    else:
                        normalized_scores = scores

                    all_scores[model_name] = normalized_scores
                    all_labels[model_name] = labels

                    logger.info(f"  ✅ {model_name}: {sum(labels)} anomalies detected")

                except Exception as e:
                    logger.error(f"  ❌ {model_name} failed: {e}")
                    continue

            if not all_scores:
                return {
                    'anomalies_detected': 0,
                    'message': 'All detection models failed',
                    'details': {},
                    'success': False
                }

            # Ensemble scoring
            ensemble_scores = np.mean(list(all_scores.values()), axis=0)

            # Ensemble labels (majority vote)
            ensemble_labels = []
            for i in range(len(user_ids)):
                votes = [all_labels[m][i] for m in all_labels.keys()]
                ensemble_labels.append(1 if sum(votes) >= len(votes)/2 else 0)

            ensemble_labels = np.array(ensemble_labels)

            # Detect and create anomaly alerts
            anomalies_detected = 0
            anomaly_details = {}

            for i, user_id in enumerate(user_ids):
                score = float(ensemble_scores[i])
                is_anomaly = (ensemble_labels[i] == 1 or score >= threshold)

                if is_anomaly:
                    # Check if recent anomaly exists
                    recent_anomaly = db.anomaly_alerts.find_one({
                        'user_id': user_id,
                        'status': 'open',
                        'detected_at': {'$gte': datetime.utcnow() - timedelta(hours=24)}
                    })

                    if not recent_anomaly:
                        features = user_features_list[i]
                        anomaly_type, severity = self._classify_anomaly(features, score)
                        top_features = self._get_top_anomalous_features(features, df)

                        alert = AnomalyAlert(
                            user_id=user_id,
                            username=user_data[user_id]['username'],
                            anomaly_type=anomaly_type,
                            anomaly_score=score,
                            details={
                                'severity': severity,
                                'ensemble_score': score,
                                'model_votes': {m: int(all_labels[m][i]) for m in all_labels.keys()},
                                'model_scores': {m: float(all_scores[m][i]) for m in all_scores.keys()},
                                'features': features,
                                'top_anomalous_features': top_features,
                                'detection_method': 'Enhanced Ensemble',
                                'lookback_days': lookback_days
                            }
                        )

                        db.anomaly_alerts.insert_one(alert.to_dict())
                        anomalies_detected += 1

                        anomaly_details[user_id] = {
                            'username': user_data[user_id]['username'],
                            'score': score,
                            'type': anomaly_type,
                            'severity': severity
                        }

                        # Auto-suspend if critical
                        if severity == 'critical' and score >= self.config['critical_threshold']:
                            db.users.update_one(
                                {'_id': ObjectId(user_id)},
                                {'$set': {'status': 'suspended'}}
                            )
                            logger.warning(f"⚠️ Auto-suspended user: {user_data[user_id]['username']}")

            self.is_fitted = True
            self._save_models()

            result = {
                'anomalies_detected': anomalies_detected,
                'users_analyzed': len(user_ids),
                'threshold': threshold,
                'lookback_days': lookback_days,
                'models_used': list(self.models.keys()),
                'details': anomaly_details,
                'success': True
            }

            logger.info(f"\n✅ Detection complete: {anomalies_detected} new anomalies found")
            return result

        except Exception as e:
            logger.error(f"Critical error in anomaly detection: {e}", exc_info=True)
            return {
                'anomalies_detected': 0,
                'message': f'Detection failed: {str(e)}',
                'details': {},
                'success': False,
                'error': str(e)
            }

    def _classify_anomaly(self, features, score):
        """Classify anomaly type and severity with safe defaults"""
        try:
            # Check specific indicators
            if features.get('failed_login_count', 0) > 5:
                type_ = 'login_pattern'
                severity = 'high' if features['failed_login_count'] > 10 else 'medium'
            elif features.get('evidence_view_count', 0) > 100:
                type_ = 'evidence_access'
                severity = 'critical' if features['evidence_view_count'] > 200 else 'high'
            elif features.get('osint_query_count', 0) > 150:
                type_ = 'osint_abuse'
                severity = 'high' if features['osint_query_count'] > 300 else 'medium'
            elif features.get('night_logins', 0) > 15:
                type_ = 'unusual_hours'
                severity = 'medium'
            elif features.get('burst_score', 0) > 0.5:
                type_ = 'activity_burst'
                severity = 'high' if features['burst_score'] > 0.7 else 'medium'
            elif features.get('unique_ip_count', 0) > 10:
                type_ = 'ip_switching'
                severity = 'high' if features['unique_ip_count'] > 20 else 'medium'
            elif features.get('download_to_view_ratio', 0) > 0.8:
                type_ = 'data_exfiltration'
                severity = 'critical'
            else:
                type_ = 'general_anomaly'
                severity = 'medium'

            # Adjust severity based on score
            if score >= 0.9:
                severity = 'critical'
            elif score >= 0.8 and severity == 'medium':
                severity = 'high'

            return type_, severity
        except Exception as e:
            logger.error(f"Error classifying anomaly: {e}")
            return 'unknown', 'medium'

    def _get_top_anomalous_features(self, features, df, top_n=5):
        """Identify most anomalous features with error handling"""
        try:
            anomalous_features = []

            for feature_name, value in features.items():
                if feature_name in df.columns:
                    col_mean = df[feature_name].mean()
                    col_std = df[feature_name].std()

                    if col_std > 0:
                        z_score = abs((value - col_mean) / col_std)
                        if z_score > 2:
                            anomalous_features.append({
                                'feature': feature_name,
                                'value': value,
                                'z_score': float(z_score),
                                'mean': float(col_mean),
                                'std': float(col_std)
                            })

            anomalous_features.sort(key=lambda x: x['z_score'], reverse=True)
            return anomalous_features[:top_n]
        except Exception as e:
            logger.error(f"Error getting top features: {e}")
            return []

    def _save_models(self):
        """Save trained models to disk"""
        try:
            model_file = os.path.join(self.model_path, 'anomaly_models.pkl')
            with open(model_file, 'wb') as f:
                pickle.dump({
                    'models': self.models,
                    'scaler': self.scaler,
                    'feature_names': self.feature_names,
                    'config': self.config
                }, f)
            logger.info(f"✅ Models saved to {model_file}")
        except Exception as e:
            logger.error(f"Error saving models: {e}")

    def load_models(self):
        """Load trained models from disk"""
        try:
            model_file = os.path.join(self.model_path, 'anomaly_models.pkl')
            if os.path.exists(model_file):
                with open(model_file, 'rb') as f:
                    data = pickle.load(f)
                    self.models = data['models']
                    self.scaler = data['scaler']
                    self.feature_names = data['feature_names']
                    self.config.update(data.get('config', {}))
                    self.is_fitted = True
                logger.info(f"✅ Models loaded from {model_file}")
                return True
        except Exception as e:
            logger.error(f"Error loading models: {e}")
        return False


# Instantiate detector
anomaly_detector = EnhancedAnomalyDetector()