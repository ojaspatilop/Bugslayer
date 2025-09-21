from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pandas as pd
import re

app = Flask(__name__)
CORS(app) # Enable Cross-Origin Resource Sharing

print("Loading RETRAINED ML models and tokenizer...")
try:
    # --- Using the v2 models ---
    xgb_model = joblib.load('xgb_model_v2.joblib')
    bilstm_model = load_model('bilstm_model_v2.keras')
    tokenizer = joblib.load('tokenizer_v2.joblib')
    print("All RETRAINED ML assets loaded successfully!")
except Exception as e:
    print(f"CRITICAL ERROR: Could not load the new v2 model assets: {e}")

def prepare_for_xgb(payload):
    features = {}
    features['payload_length'] = len(payload)
    char_map = {'<':'lessthan', '>':'greaterthan', "'":'singlequote', '"':'doublequote', '(':'leftparen', ')':'rightparen', ';':'semicolon', '&':'ampersand', '#':'hash', '=':'equals'}
    for char, name in char_map.items():
        features[f'char_{name}_count'] = payload.count(char)
    keywords = ['script', 'alert', 'onerror', 'onload', 'select', 'union', 'from', 'where', 'or', 'and', 'sleep']
    for keyword in keywords:
        features[f'keyword_{keyword}_count'] = payload.lower().count(keyword)
    return pd.DataFrame([features])

def prepare_for_bilstm(payload):
    sequence = tokenizer.texts_to_sequences([payload])
    return pad_sequences(sequence, maxlen=150, padding='post', truncating='post')

@app.route('/scan', methods=['POST'])
def scan_payload():
    data = request.get_json()
    
    # *** THIS IS THE CORRECTED LINE ***
    if not data or 'payload' not in data:
        return jsonify({'error': 'Invalid input. "payload" key is required.'}), 400
    
    payload = data['payload']

    # Pre-filter for obviously safe inputs
    if len(payload) < 15 and not re.search(r'[<>\'()&;=#]', payload):
        return jsonify({'final_verdict': 'Benign (Pre-filtered)'})

    # ML Predictions using the new models
    xgb_features = prepare_for_xgb(payload)
    xgb_pred = int(xgb_model.predict(xgb_features)[0])
    
    bilstm_sequence = prepare_for_bilstm(payload)
    bilstm_pred_prob = bilstm_model.predict(bilstm_sequence)[0][0]
    bilstm_pred = 1 if bilstm_pred_prob > 0.5 else 0

    final_verdict = "Malicious" if (xgb_pred == 1 or bilstm_pred == 1) else "Benign"
    
    return jsonify({
        'payload': payload,
        'final_verdict': final_verdict
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)