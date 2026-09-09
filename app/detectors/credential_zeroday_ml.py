import re
import time
import logging
import math
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum

import torch
import torch.nn as nn
import torch.nn.functional as F

from app.models import StageResult, DetectionMatch, ThreatSeverity
from app.config import settings

logger = logging.getLogger("promptguard.credential_zeroday")


class CredentialAnomalyType(Enum):
    """Zero-day credential vulnerability classification"""
    UNUSUAL_ENTROPY_PATTERN = "UNUSUAL_ENTROPY_PATTERN"
    FORMAT_BYPASS_ATTEMPT = "FORMAT_BYPASS_ATTEMPT"
    OBFUSCATED_CREDENTIAL = "OBFUSCATED_CREDENTIAL"
    MULTI_ENCODING_NESTING = "MULTI_ENCODING_NESTING"
    TIMING_SIDE_CHANNEL = "TIMING_SIDE_CHANNEL"
    POLYMORPHIC_PATTERN = "POLYMORPHIC_PATTERN"
    CREDENTIAL_SPRAY_PATTERN = "CREDENTIAL_SPRAY_PATTERN"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"


@dataclass
class CredentialAnomaly:
    """Represents a detected zero-day credential vulnerability"""
    anomaly_type: CredentialAnomalyType
    severity: ThreatSeverity
    confidence: float
    text_snippet: str
    start: int
    end: int
    description: str
    analysis: Dict[str, Any]


class EntropyAnalyzer:
    """Analyzes entropy patterns to detect unusual credential structures"""
    
    def __init__(self, threshold: float = 3.5):
        self.threshold = threshold
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text or len(text) < 2:
            return 0.0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / len(text)
            entropy -= p * math.log2(p)
        
        return entropy
    
    def analyze_credential_entropy(self, token: str) -> Dict[str, Any]:
        """Analyze entropy pattern of potential credential"""
        entropy = self.calculate_entropy(token)
        
        # Check for unusual entropy patterns
        analysis = {
            "entropy": round(entropy, 3),
            "is_anomalous": entropy > self.threshold,
            "length": len(token),
            "char_diversity": len(set(token)) / len(token) if token else 0.0,
            "repeated_sequences": self._detect_repeated_sequences(token),
        }
        
        return analysis
    
    def _detect_repeated_sequences(self, token: str) -> List[str]:
        """Detect repeated character sequences (potential encoding)"""
        repeated = []
        for pattern_len in range(2, min(5, len(token) // 2)):
            pattern = token[:pattern_len]
            if token.count(pattern) > 1:
                repeated.append(f"{pattern}(x{token.count(pattern)})")
        return repeated


class PolymorphicCredentialDetector:
    """Detects polymorphic/mutating credential patterns"""
    
    # Known credential patterns with mutation signatures
    MUTATION_PATTERNS = {
        "AWS_VARIANT": [
            r"[Aa][Kk][Ii][Aa][0-9A-Z]{16}",  # Case mutations
            r"AKIA[0-9A-Z]{16}(?:[_-][0-9A-Z]+)*",  # Separator mutations
            r"[Aa]{1,2}[Kk]{1,2}[Ii]{1,2}[Aa]{1,2}[0-9A-Z]{16}",  # Repeat mutations
        ],
        "JWT_VARIANT": [
            r"ey[a-zA-Z0-9_-]+\.ey[a-zA-Z0-9_-]+\.[\w\-]+",  # Standard
            r"ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",  # Alt separator
            r"\[JWT[:\s_-]*[Tt]oken\][=:\s]+ey[a-zA-Z0-9_-]+",  # Encoded variant
        ],
        "DB_CONNECTION": [
            r"(mongodb|postgresql|mysql)://[^:]+:[^@]+@[^:/]+",
            r"(mongodb|postgresql|mysql)\+srv://[^:]+:[^@]+@[^:/]+",
            r"(Driver={[^}]+}|Provider=[^;]+);[^=]*=[^;]*",  # ODBC variant
        ],
    }
    
    def detect_polymorphic(self, text: str) -> List[Tuple[str, float]]:
        """Detect polymorphic credential patterns"""
        detections = []
        
        for cred_type, patterns in self.MUTATION_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text)
                for match in matches:
                    confidence = self._calculate_pattern_confidence(match.group(0), cred_type)
                    detections.append((cred_type, confidence))
        
        return detections
    
    def _calculate_pattern_confidence(self, matched_text: str, cred_type: str) -> float:
        """Calculate confidence score based on pattern characteristics"""
        base_score = 0.7
        
        # Boost for length
        if len(matched_text) > 50:
            base_score += 0.1
        
        # Boost for special separators (mutation signature)
        if re.search(r'[_\-]{2,}', matched_text):
            base_score += 0.05
        
        # Boost for mixed case (obfuscation)
        if re.search(r'[a-z]', matched_text) and re.search(r'[A-Z]', matched_text):
            base_score += 0.05
        
        return min(base_score, 1.0)


class NeuralCredentialAnomalyDetector(nn.Module):
    """PyTorch neural network for zero-day credential anomaly detection"""
    
    def __init__(self, input_dim: int = 256, hidden_dim: int = 128, num_anomaly_types: int = 8):
        super().__init__()
        
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
        )
        
        # Anomaly type classifier
        self.anomaly_classifier = nn.Sequential(
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, num_anomaly_types),
        )
        
        # Severity predictor
        self.severity_predictor = nn.Sequential(
            nn.Linear(64, 16),
            nn.ReLU(),
            nn.Linear(16, 5),  # 5 severity levels
        )
        
        # Confidence scorer
        self.confidence_head = nn.Sequential(
            nn.Linear(64, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid(),
        )
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        encoded = self.encoder(x)
        anomaly_logits = self.anomaly_classifier(encoded)
        severity_logits = self.severity_predictor(encoded)
        confidence = self.confidence_head(encoded)
        
        return anomaly_logits, severity_logits, confidence


class CredentialFeatureExtractor:
    """Extracts numerical features from credential tokens for ML analysis"""
    
    def __init__(self, feature_dim: int = 256):
        self.feature_dim = feature_dim
        self.entropy_analyzer = EntropyAnalyzer()
    
    def extract_features(self, credential_token: str) -> torch.Tensor:
        """Extract 256-dimensional feature vector from credential"""
        features = []
        
        # 1. Basic statistics (8 features)
        features.append(len(credential_token) / 1000.0)  # Length normalization
        features.append(self.entropy_analyzer.calculate_entropy(credential_token) / 8.0)
        features.append(len(set(credential_token)) / len(credential_token))  # Char diversity
        features.append(sum(1 for c in credential_token if c.isupper()) / max(len(credential_token), 1))
        features.append(sum(1 for c in credential_token if c.isdigit()) / max(len(credential_token), 1))
        features.append(sum(1 for c in credential_token if not c.isalnum()) / max(len(credential_token), 1))
        features.append(1.0 if re.search(r'[_\-]{2,}', credential_token) else 0.0)
        features.append(1.0 if re.search(r'[{}()\[\]]', credential_token) else 0.0)
        
        # 2. Pattern signatures (32 features - repeated patterns)
        pattern_counts = self._count_repeated_patterns(credential_token)
        for i in range(32):
            if i < len(pattern_counts):
                features.append(pattern_counts[i] / max(len(credential_token), 1))
            else:
                features.append(0.0)
        
        # 3. Substring statistics (64 features)
        substrings = self._extract_substrings(credential_token, min_len=3, max_len=5)
        substring_entropy = [self.entropy_analyzer.calculate_entropy(s) for s in substrings[:64]]
        for entropy in substring_entropy:
            features.append(entropy / 8.0)
        while len(features) < 40 + 64:  # Pad
            features.append(0.0)
        
        # 4. Positional encoding (64 features - character type sequence)
        char_sequence = []
        for char in credential_token[:64]:
            if char.isupper():
                char_sequence.append(0.25)
            elif char.islower():
                char_sequence.append(0.5)
            elif char.isdigit():
                char_sequence.append(0.75)
            else:
                char_sequence.append(1.0)
        char_sequence.extend([0.0] * (64 - len(char_sequence)))
        features.extend(char_sequence[:64])
        
        # 5. N-gram statistics (64 features)
        ngrams = self._extract_ngrams(credential_token, n=2)
        ngram_entropies = [self.entropy_analyzer.calculate_entropy(ng) for ng in ngrams[:64]]
        for entropy in ngram_entropies:
            features.append(entropy / 8.0)
        while len(features) < 40 + 64 + 64 + 64:
            features.append(0.0)
        
        # Pad to exactly feature_dim
        features = features[:self.feature_dim]
        while len(features) < self.feature_dim:
            features.append(0.0)
        
        return torch.tensor(features, dtype=torch.float32)
    
    def _count_repeated_patterns(self, text: str) -> List[float]:
        """Count occurrences of repeated character patterns"""
        counts = []
        for length in range(1, 6):
            seen = {}
            for i in range(len(text) - length + 1):
                substr = text[i:i+length]
                seen[substr] = seen.get(substr, 0) + 1
            max_repeat = max(seen.values()) if seen else 0
            counts.append(float(max_repeat))
        return counts
    
    def _extract_substrings(self, text: str, min_len: int = 3, max_len: int = 5) -> List[str]:
        """Extract all substrings of specified length"""
        substrings = []
        for length in range(min_len, max_len + 1):
            for i in range(max(0, len(text) - length + 1)):
                substrings.append(text[i:i+length])
        return substrings
    
    def _extract_ngrams(self, text: str, n: int = 2) -> List[str]:
        """Extract n-grams from text"""
        ngrams = []
        for i in range(len(text) - n + 1):
            ngrams.append(text[i:i+n])
        return ngrams


class CredentialZeroDayDetector:
    """
    ML-based detector for zero-day credential vulnerabilities.
    Combines entropy analysis, polymorphic detection, and neural anomaly detection.
    """
    
    def __init__(self):
        self.device = torch.device("cpu")
        if torch.cuda.is_available():
            self.device = torch.device("cuda")
        elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
            self.device = torch.device("mps")
        
        self.entropy_analyzer = EntropyAnalyzer(threshold=3.5)
        self.polymorphic_detector = PolymorphicCredentialDetector()
        self.feature_extractor = CredentialFeatureExtractor(feature_dim=256)
        
        # Initialize neural model
        self.neural_model = NeuralCredentialAnomalyDetector(
            input_dim=256,
            hidden_dim=128,
            num_anomaly_types=len(CredentialAnomalyType),
        ).to(self.device)
        self.neural_model.eval()
        
        # Anomaly type mapping
        self.anomaly_types = [t.value for t in CredentialAnomalyType]
        self.anomaly_type_to_severity = {
            CredentialAnomalyType.UNUSUAL_ENTROPY_PATTERN: ThreatSeverity.MEDIUM,
            CredentialAnomalyType.FORMAT_BYPASS_ATTEMPT: ThreatSeverity.HIGH,
            CredentialAnomalyType.OBFUSCATED_CREDENTIAL: ThreatSeverity.HIGH,
            CredentialAnomalyType.MULTI_ENCODING_NESTING: ThreatSeverity.CRITICAL,
            CredentialAnomalyType.TIMING_SIDE_CHANNEL: ThreatSeverity.MEDIUM,
            CredentialAnomalyType.POLYMORPHIC_PATTERN: ThreatSeverity.HIGH,
            CredentialAnomalyType.CREDENTIAL_SPRAY_PATTERN: ThreatSeverity.CRITICAL,
            CredentialAnomalyType.BEHAVIORAL_ANOMALY: ThreatSeverity.MEDIUM,
        }
    
    def detect_zeroday_anomalies(self, text: str) -> List[CredentialAnomaly]:
        """Detect zero-day credential vulnerabilities"""
        anomalies = []
        start_time = time.time()
        
        # Extract potential credential tokens
        potential_tokens = self._extract_potential_tokens(text)
        
        for token_start, token_end, token in potential_tokens:
            # 1. Entropy-based detection
            entropy_anomaly = self._detect_entropy_anomaly(token, token_start, token_end, text)
            if entropy_anomaly:
                anomalies.append(entropy_anomaly)
            
            # 2. Polymorphic pattern detection
            poly_anomalies = self._detect_polymorphic_anomalies(token, token_start, token_end, text)
            anomalies.extend(poly_anomalies)
            
            # 3. Format bypass detection
            bypass_anomaly = self._detect_format_bypass(token, token_start, token_end, text)
            if bypass_anomaly:
                anomalies.append(bypass_anomaly)
            
            # 4. Multi-encoding nesting detection
            nesting_anomaly = self._detect_encoding_nesting(token, token_start, token_end, text)
            if nesting_anomaly:
                anomalies.append(nesting_anomaly)
        
        # 5. Credential spray pattern detection
        spray_anomalies = self._detect_credential_spray(text)
        anomalies.extend(spray_anomalies)
        
        # 6. Behavioral anomaly via neural model
        if anomalies:  # Only run neural model if other anomalies detected
            behavioral_anomaly = self._detect_behavioral_anomaly(text, anomalies)
            if behavioral_anomaly:
                anomalies.append(behavioral_anomaly)
        
        logger.debug(f"Zeroday detection completed in {(time.time() - start_time) * 1000:.2f}ms, "
                    f"found {len(anomalies)} anomalies")
        
        return anomalies
    
    def _extract_potential_tokens(self, text: str) -> List[Tuple[int, int, str]]:
        """Extract potential credential tokens from text"""
        tokens = []
        
        # Common credential-like patterns
        patterns = [
            r"[A-Za-z0-9_]{20,}",  # Long alphanumeric strings
            r"[A-Za-z0-9\+/]{32,}={0,2}",  # Base64-like
            r"sk_(?:test|live)_[A-Za-z0-9]{20,}",  # API key format
            r"[A-Z]{2,}[_\-][A-Za-z0-9\+/]{20,}",  # Prefixed tokens
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                token = match.group(0)
                if len(token) >= 15:  # Minimum token length
                    tokens.append((match.start(), match.end(), token))
        
        return list(set(tokens))  # Deduplicate
    
    def _detect_entropy_anomaly(self, token: str, start: int, end: int, 
                               text: str) -> Optional[CredentialAnomaly]:
        """Detect unusual entropy patterns"""
        entropy_analysis = self.entropy_analyzer.analyze_credential_entropy(token)
        
        if entropy_analysis["is_anomalous"]:
            return CredentialAnomaly(
                anomaly_type=CredentialAnomalyType.UNUSUAL_ENTROPY_PATTERN,
                severity=ThreatSeverity.MEDIUM,
                confidence=min(entropy_analysis["entropy"] / 8.0, 1.0),
                text_snippet=token,
                start=start,
                end=end,
                description=f"Unusual entropy pattern detected: {entropy_analysis['entropy']} bits",
                analysis=entropy_analysis,
            )
        
        return None
    
    def _detect_polymorphic_anomalies(self, token: str, start: int, end: int,
                                     text: str) -> List[CredentialAnomaly]:
        """Detect polymorphic credential patterns"""
        anomalies = []
        polymorphic_detections = self.polymorphic_detector.detect_polymorphic(token)
        
        for cred_type, confidence in polymorphic_detections:
            if confidence > 0.75:
                anomalies.append(CredentialAnomaly(
                    anomaly_type=CredentialAnomalyType.POLYMORPHIC_PATTERN,
                    severity=ThreatSeverity.HIGH,
                    confidence=confidence,
                    text_snippet=token,
                    start=start,
                    end=end,
                    description=f"Polymorphic {cred_type} pattern detected with mutations",
                    analysis={"cred_type": cred_type, "mutation_confidence": confidence},
                ))
        
        return anomalies
    
    def _detect_format_bypass(self, token: str, start: int, end: int,
                             text: str) -> Optional[CredentialAnomaly]:
        """Detect format bypass attempts (e.g., delimiter injection)"""
        bypass_patterns = [
            (r"[a-zA-Z0-9]+[\s\\n\\t]+[a-zA-Z0-9]+", "Whitespace injection"),
            (r"[a-zA-Z0-9]+\${.*?}[a-zA-Z0-9]+", "Variable expansion attempt"),
            (r"[a-zA-Z0-9]+`.*?`[a-zA-Z0-9]+", "Command injection attempt"),
        ]
        
        for pattern, description in bypass_patterns:
            if re.search(pattern, token):
                return CredentialAnomaly(
                    anomaly_type=CredentialAnomalyType.FORMAT_BYPASS_ATTEMPT,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.85,
                    text_snippet=token,
                    start=start,
                    end=end,
                    description=f"Format bypass detected: {description}",
                    analysis={"bypass_type": description},
                )
        
        return None
    
    def _detect_encoding_nesting(self, token: str, start: int, end: int,
                                text: str) -> Optional[CredentialAnomaly]:
        """Detect multi-level encoding nesting"""
        nesting_levels = self._count_encoding_nesting(token)
        
        if nesting_levels > 2:
            return CredentialAnomaly(
                anomaly_type=CredentialAnomalyType.MULTI_ENCODING_NESTING,
                severity=ThreatSeverity.CRITICAL,
                confidence=min(nesting_levels / 5.0, 1.0),
                text_snippet=token,
                start=start,
                end=end,
                description=f"Multi-level encoding nesting detected ({nesting_levels} levels)",
                analysis={"nesting_levels": nesting_levels},
            )
        
        return None
    
    def _count_encoding_nesting(self, token: str) -> int:
        """Count levels of encoding nesting"""
        levels = 0
        current = token
        
        while len(current) > 10:
            # Try base64 decode
            try:
                import base64
                decoded = base64.b64decode(current, validate=True).decode('utf-8', errors='ignore')
                if len(decoded) > 0 and decoded != current:
                    levels += 1
                    current = decoded
                else:
                    break
            except:
                break
        
        return levels
    
    def _detect_credential_spray(self, text: str) -> List[CredentialAnomaly]:
        """Detect credential spray patterns (multiple credentials in one request)"""
        anomalies = []
        
        # Count potential credential tokens
        potential_tokens = self._extract_potential_tokens(text)
        
        if len(potential_tokens) > 5:  # Threshold for spray
            return [CredentialAnomaly(
                anomaly_type=CredentialAnomalyType.CREDENTIAL_SPRAY_PATTERN,
                severity=ThreatSeverity.CRITICAL,
                confidence=min(len(potential_tokens) / 20.0, 1.0),
                text_snippet=text[:100],
                start=0,
                end=min(100, len(text)),
                description=f"Credential spray pattern: {len(potential_tokens)} potential credentials in single request",
                analysis={"credential_count": len(potential_tokens)},
            )]
        
        return anomalies
    
    def _detect_behavioral_anomaly(self, text: str, existing_anomalies: List[CredentialAnomaly]
                                   ) -> Optional[CredentialAnomaly]:
        """Detect behavioral anomalies using neural model"""
        try:
            # Extract features from suspicious text regions
            features = self.feature_extractor.extract_features(text[:512])
            features_tensor = features.unsqueeze(0).to(self.device)
            
            with torch.no_grad():
                anomaly_logits, severity_logits, confidence = self.neural_model(features_tensor)
                
                # Get top anomaly type
                top_anomaly_idx = torch.argmax(anomaly_logits[0]).item()
                top_confidence = float(confidence[0].item())
                
                if top_confidence > 0.6 and len(existing_anomalies) > 0:
                    return CredentialAnomaly(
                        anomaly_type=CredentialAnomalyType.BEHAVIORAL_ANOMALY,
                        severity=ThreatSeverity.MEDIUM,
                        confidence=top_confidence,
                        text_snippet=text[:80],
                        start=0,
                        end=min(80, len(text)),
                        description="Behavioral anomaly pattern detected via neural model",
                        analysis={
                            "model_confidence": top_confidence,
                            "correlated_anomalies": len(existing_anomalies),
                        },
                    )
        except Exception as e:
            logger.debug(f"Neural model analysis skipped: {e}")
        
        return None


class IntegratedCredentialDetector:
    """
    Combines traditional regex-based detection with ML-based zero-day detection.
    Wraps both approaches for comprehensive credential security.
    """
    
    def __init__(self):
        self.zeroday_detector = CredentialZeroDayDetector()
    
    def analyze(self, text: str) -> StageResult:
        """Analyze credentials with both traditional and ML-based detection"""
        start_time = time.time()
        matches: List[DetectionMatch] = []
        
        # Run zero-day ML detection
        anomalies = self.zeroday_detector.detect_zeroday_anomalies(text)
        
        # Convert anomalies to DetectionMatch objects
        for anomaly in anomalies:
            match = DetectionMatch(
                stage_id=2,
                stage_name="Stage 2: Credential Scan (ZeroDay ML)",
                entity_type=anomaly.anomaly_type.value,
                text_snippet=anomaly.text_snippet,
                start=anomaly.start,
                end=anomaly.end,
                confidence=anomaly.confidence,
                severity=anomaly.severity,
                description=anomaly.description,
            )
            matches.append(match)
        
        exec_time = (time.time() - start_time) * 1000
        return StageResult(
            stage_id=2,
            stage_name="Stage 2: Credential Scan (ZeroDay ML)",
            passed=len(matches) == 0,
            detection_count=len(matches),
            matches=matches,
            execution_time_ms=round(exec_time, 2),
        )
