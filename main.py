from flask import Flask, request, jsonify
import os
import hashlib
import hmac

app = Flask(__name__)

# Get environment variables
SLACK_SIGNING_SECRET = os.environ.get('SLACK_SIGNING_SECRET', '')

def verify_slack_request(request):
    """Verify that the request actually comes from Slack"""
    slack_signature = request.headers.get('X-Slack-Signature', '')
    slack_request_timestamp = request.headers.get('X-Slack-Request-Timestamp', '')
    
    if not slack_signature or not slack_request_timestamp:
        return False
    
    # Form the base string
    basestring = f"v0:{slack_request_timestamp}:{request.get_data(as_text=True)}"
    
    # Create a new HMAC
    my_signature = 'v0=' + hmac.new(
        bytes(SLACK_SIGNING_SECRET, 'utf-8'),
        bytes(basestring, 'utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(my_signature, slack_signature)

@app.route('/')
def index():
    return 'Shipergy Slack Bot is running!'

@app.route('/slack/events', methods=['POST'])
def slack_events():
    # Get the request data
    slack_event = request.json
    
    # Handle Slack URL verification challenge
    if 'challenge' in slack_event:
        return jsonify({'challenge': slack_event['challenge']})
    
    # Verify the request is from Slack
    if not verify_slack_request(request):
        return 'Unauthorized', 403
    
    # For now, just acknowledge all events
    return '', 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
