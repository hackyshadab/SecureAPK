import os
import tempfile
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from analysis.static_analyzer import analyze_apk
import joblib
import pandas as pd
import shap
import requests
from analysis.vt_lookup import vt_lookup_sha256 
from flask import render_template

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

def malwarebazaar_lookup_sha256(sha256):

        try:
            json_data = resp.json()
        except ValueError:
            return {
                'detections': 0,
                'query_status': 'invalid_json',
                'raw': resp.text
            }

        query_status = json_data.get('query_status', 'unknown')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS




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
  
        mb_result = malwarebazaar_lookup_sha256(sha256)

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
    return render_template('landing.html')

@app.route('/dashboard')
def console():
    return render_template('index.html')

# ------------------------
# Run App
# ------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

