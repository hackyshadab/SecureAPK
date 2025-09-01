


import os
import tempfile
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from analysis.static_analyzer import analyze_apk
import joblib
import pandas as pd
import shap
import requests
from analysis.vt_lookup import vt_lookup_sha256  # production VT integration
from flask import render_template

# ------------------------
# Config
# ------------------------
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'apk'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB
MODEL_FILE = 'datamodel.pkl'
TRUSTED_DATA_FILE = 'trusted_bank_data.json' 

# ------------------------
# Load ML model
# ------------------------
ml_bundle = joblib.load(MODEL_FILE)
clf = ml_bundle['model']
scaler = ml_bundle['scaler']
features = ml_bundle['features']
explainer = shap.TreeExplainer(clf)

# ------------------------
# Flask App
# ------------------------
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# ------------------------
# Helpers
# ------------------------

def malwarebazaar_lookup_sha256(sha256, api_key=None):
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": sha256}
    headers = {"API-Key": api_key} if api_key else {}
    try:
        resp = requests.post(url, data=data, headers=headers, timeout=15)
        if resp.status_code == 200:
            json_data = resp.json()
            detections = len(json_data.get("data", [])) if "data" in json_data else 0
            return {"detections": detections, "raw": json_data}
        else:
            return {"detections": 0, "raw": {"error": resp.text}}
    except Exception as e:
        return {"detections": 0, "raw": {"error": str(e)}}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



def combine_ml_vt_mb(ml_prob, vt_detections, vt_total, mb_detections):
    vt_score = (vt_detections/vt_total) if vt_total>0 else 0
    mb_score = 1.0 if mb_detections > 0 else 0
    final_score = 0.7*ml_prob + 0.15*vt_score + 0.15*mb_score
    final_score = min(final_score, 1.0)

    if vt_detections > 5 or mb_detections > 0:
        decision = "Likely Malware (Confirmed)"
    elif vt_detections==0 and mb_detections==0 and ml_prob>0.7:
        decision = "Suspicious (New Malware?)"
    elif vt_detections==0 and mb_detections==0 and ml_prob<0.3:
        decision = "Likely Safe"
    else:
        decision = "Potentially Risky"
    return final_score, decision


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        # ------------------------
        # Static Analysis
        # ------------------------
        static_result = analyze_apk(filepath, trusted_data_path=TRUSTED_DATA_FILE)

        # VirusTotal lookup
        sha256 = static_result.sha256
        vt_result = vt_lookup_sha256(sha256)
        static_result.vt = vt_result


        mb_api_key = "27d581095c588795cc923982eda9b787ceb6ab2af6fdb7ab"  
        mb_result = malwarebazaar_lookup_sha256(sha256, api_key=mb_api_key)

        # ------------------------
        # Prepare ML features
        # ------------------------
        df_features = pd.DataFrame([{
            'permissions_score': len(static_result.permissions),
            'entropy': static_result.entropy_classes_dex,
            'cert_mismatch': 0 if static_result.cert_trusted_match else 1,
            'suspicious_strings': len(static_result.suspicious.get('strings', [])),
            'icon_similarity': static_result.icon_similarity_score,
            'ip_count': static_result.suspicious.get('ip_count', 0),
            'url_count': static_result.suspicious.get('url_count', 0),
            'dangerous_permissions': len(static_result.dangerous_permissions),
            'cert_trusted_match': int(static_result.cert_trusted_match),
            'perm_dangerous_count': len(static_result.dangerous_permissions),
            'perm_normal_count': len(static_result.permissions) - len(static_result.dangerous_permissions),
            'perm_custom_count': 0
        }])

        # Scale features
        X_scaled = scaler.transform(df_features[features])

        # ML prediction
        ml_prob = clf.predict_proba(X_scaled)[0][1]

        # SHAP explanations
        shap_vals = explainer.shap_values(X_scaled)
        shap_for_class1 = shap_vals[1] if isinstance(shap_vals, list) else shap_vals
        shap_values_sample = shap_for_class1[0].flatten()
        explanations = [
            f"High {feat} contributes to fake prediction"
            for i, feat in enumerate(features) if shap_values_sample[i] > 0
        ]

        # ------------------------
        # Combine ML + VT + MalwareBazaar
        # ------------------------
        final_score, decision = combine_ml_vt_mb(
            ml_prob,
            vt_result['detections'],
            vt_result['total'],
            mb_result['detections']
        )

        # ------------------------
        # Build response
        # ------------------------
        response = {
            'meta': {
                'sha256': static_result.sha256,
                'package': static_result.package,
                'app_label': static_result.app_label,
                'version_name': static_result.version_name,
                'version_code': static_result.version_code
            },
            'analysis': {
                'permissions': static_result.permissions,
                'dangerous_permissions': static_result.dangerous_permissions,
                'cert_fingerprint': static_result.cert_fingerprint,
                'cert_trusted_match': static_result.cert_trusted_match,
                'icon_hash': static_result.icon_hash,
                'icon_similarity_score': static_result.icon_similarity_score,
                'entropy_classes_dex': static_result.entropy_classes_dex,
                'suspicious': static_result.suspicious,
                'vt': static_result.vt,
                'malwarebazaar': mb_result
            },
            'model': {
                'probability_fake': round(ml_prob*100, 2),
                'final_score': round(final_score*100, 2),
                'decision': decision,
                'explanations': explanations
            }
        }

        return jsonify(response)

    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


# Health check
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status':'ok'})


@app.route('/')
def index():
    return render_template('index.html')

# ------------------------
# Run App
# ------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

