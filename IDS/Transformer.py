from sklearn.base import BaseEstimator, TransformerMixin
import pandas as pd
import numpy as np
# =========================
# 1. Transformeur pour le timestamp
# =========================
class TimestampTransformer(BaseEstimator, TransformerMixin):
    def __init__(self, column):
        self.column = column
        self.day_mapping = {
            'monday': 1, 'tuesday': 2, 'wednesday': 3, 'thursday': 4,
            'friday': 5, 'saturday': 6, 'sunday': 7
        }
    
    def fit(self, X, y=None):
        return self
    
    def transform(self, X):
        def parse_timestamp(ts):
            if pd.isnull(ts):
                return [0, 0, 0, 0]
            try:
                parts = ts.strip().split()
                day_str = parts[0].lower()
                time_str = parts[1]
                jour = self.day_mapping.get(day_str, 0)
                h, m, s = map(int, time_str.split(':'))
                return [jour, h, m, s]
            except:
                return [0, 0, 0, 0]
        
        ts_values = X[self.column].apply(parse_timestamp)
        return np.vstack(ts_values.values)

# =========================
# 2. Transformeur IP
# =========================
class IpNormalizer(BaseEstimator, TransformerMixin):
    def __init__(self, column):
        self.column = column
    
    def fit(self, X, y=None):
        return self
    
    def transform(self, X):
        def normalize_ip(ip):
            if pd.isnull(ip):
                return np.zeros(4)
            octets = ip.strip().split('.')
            if len(octets) != 4 or not all(o.isdigit() for o in octets):
                return np.zeros(4)
            return np.array([int(o) for o in octets])
        
        ip_vectors = X[self.column].apply(normalize_ip)
        return np.vstack(ip_vectors.values)

# =========================
# 3. Transformeur DNS Type
# =========================
class DnsTypeEncoder(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.dns_map = {
            'DNS_TYPE_PTR': 1,
            'DNS_TYPE_A': 2,
            'DNS_TYPE_AAAA': 3,
            'missing': 0
        }
    
    def fit(self, X, y=None):
        return self
    
    def transform(self, X):
        if not hasattr(X, 'iloc'):
            X = pd.Series(X.ravel())
        result = X.fillna('missing').apply(lambda x: self.dns_map.get(x, 0))
        return result.values.reshape(-1, 1)

# =========================
# 4. Transformeur Protocole
# =========================
class ProtocolMapper(BaseEstimator, TransformerMixin):
    def __init__(self, column):
        self.column = column
        self.protocol_map = {
            'DHCP': 1, 'MDNS': 2, 'ARP': 3, 'SSDP': 4,
            'LLDP': 5, 'CDP': 6, 'STP': 7, 'WOL': 8,
            'ICMP': 9, 'SNMP': 10,
            'missing': 0
        }
    
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        result = X[self.column].fillna('missing').apply(lambda p: self.protocol_map.get(p.upper(), 0))
        return result.values.reshape(-1, 1)

# =========================
# 5. Transformeur DHCP Message
# =========================
class DhcpMessageMapper(BaseEstimator, TransformerMixin):
    def __init__(self, column):
        self.column = column
        self.dhcp_map = {
            'DISCOVER': 1,
            'REQUEST': 3,
            'DECLINE': 4,
            'UNKNOW': 8,
            'missing': 0
        }
    
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        result = X[self.column].fillna('missing').apply(lambda v: self.dhcp_map.get(v.upper(), 0))
        return result.values.reshape(-1, 1)