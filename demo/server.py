"""
AgentGuard Demo Server — Flask application showcasing live trap detection.

Run: agentguard demo --port 8080
Open: http://localhost:8080
"""

import sys
import os
import json
from flask import Flask, render_template, request, jsonify, send_from_directory

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentguard.pipeline import AgentGuard
from agentguard.config import AgentGuardConfig

guard = AgentGuard()


def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/attack-demo')
    def attack_demo():
        return render_template('attack_page.html')

    @app.route('/static/<path:filename>')
    def static_files(filename):
        return send_from_directory('static', filename)

    @app.route('/api/scan', methods=['POST'])
    def api_scan():
        data = request.get_json() or {}
        url = data.get('url')
        text = data.get('text')

        try:
            if url:
                response = guard.scan_url(url)
            elif text:
                response = guard.scan_text(text)
            else:
                return jsonify({"error": "Provide 'url' or 'text' in JSON body"}), 400

            from agentguard.trust.scorer import TrustScorer
            scorer = TrustScorer(guard.config)
            return jsonify(scorer.to_dict(response.trust_report))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/api/scan-attack-demo', methods=['GET'])
    def scan_attack_demo():
        """Pre-scan the attack demo page and return the TrustReport."""
        try:
            # Build the attack page URL
            host = request.host
            attack_url = f"http://{host}/attack-demo"
            response = guard.scan_url(attack_url)
            from agentguard.trust.scorer import TrustScorer
            scorer = TrustScorer(guard.config)
            return jsonify(scorer.to_dict(response.trust_report))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/api/scan-document', methods=['POST'])
    def scan_document():
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        file = request.files['file']
        if file.filename:
            file_bytes = file.read()
            response = guard.scan_document(file_bytes, file.filename)
            from agentguard.trust.scorer import TrustScorer
            scorer = TrustScorer(guard.config)
            return jsonify(scorer.to_dict(response.trust_report))
        return jsonify({"error": "No filename"}), 400

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8080, debug=True)
