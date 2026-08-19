import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import joblib  # type: ignore
from sklearn.ensemble import RandomForestClassifier  # type: ignore
from ml.feature_extractor import FeatureExtractor

def train_dummy_model():
    """
    Trains a baseline Random Forest model and exports to ml/dga_rf_v1.pkl.
    Owned by Member 4.
    """
    domains = [
        ("google.com", 0),
        ("microsoft.com", 0),
        ("wikipedia.org", 0),
        ("github.com", 0),
        ("cxz98qwe12a.info", 1),
        ("vbnm345qwe789zxc.biz", 1),
        ("asdfghjkl1234567.cc", 1),
        ("qwertyuiopasdfgh.ru", 1)
    ]

    X = []
    y = []
    for domain, label in domains:
        feats = FeatureExtractor.extract_features(domain)
        X.append([v for v in feats.values()])
        y.append(label)

    clf = RandomForestClassifier(n_estimators=10, random_state=42)
    clf.fit(X, y)
    joblib.dump(clf, "ml/dga_rf_v1.pkl")
    print("[ML] Baseline model trained and saved to ml/dga_rf_v1.pkl")

if __name__ == "__main__":
    train_dummy_model()
