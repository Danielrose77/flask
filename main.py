from flask import Flask, request, jsonify
import os
import hashlib
import hmac
import requests
import json
from datetime import datetime

app = Flask(__name__)

# Environment variables
SLACK_BOT_TOKEN = os.environ.get('SLACK_BOT_TOKEN', '')
SLACK_SIGNING_SECRET = os.environ.get('SLACK_SIGNING_SECRET', '')
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')

# Store pending deals (in production, use a database)
pending_deals = {}

def verify_slack_request(request):
    """Verify that the request actually comes from Slack"""
    slack_signature = request.headers.get('X-Slack-Signature', '')
    slack_request_timestamp = request.headers.get('X-Slack-Request-Timestamp', '')
    
    if not slack_signature or not slack_request_timestamp:
        return False
    
    basestring = f"v0:{slack_request_timestamp}:{request.get_data(as_text=True)}"
    my_signature = 'v0=' + hmac.new(
        bytes(SLACK_SIGNING_SECRET, 'utf-8'),
        bytes(basestring, 'utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(my_signature, slack_signature)

def send_slack_message(channel, text, thread_ts=None):
    """Send a message to Slack"""
    url = "https://slack.com/api/chat.postMessage"
    headers = {
        "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {
        "channel": channel,
        "text": text
    }
    if thread_ts:
        data["thread_ts"] = thread_ts
    
    response = requests.post(url, headers=headers, json=data)
    return response.json()

def get_thread_messages(channel, thread_ts):
    """Get all messages in a thread"""
    url = "https://slack.com/api/conversations.replies"
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}
    params = {
        "channel": channel,
        "ts": thread_ts
    }
    response = requests.get(url, headers=headers, params=params)
    return response.json()

@app.route('/')
def index():
    return 'Shipergy Deal Tracker Bot is running!'

@app.route('/slack/events', methods=['POST'])
def slack_events():
    slack_event = request.json
    
    # Handle URL verification
    if 'challenge' in slack_event:
        return jsonify({'challenge': slack_event['challenge']})
    
    # Verify reque
