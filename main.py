from flask import Flask, request, jsonify
import os
import hashlib
import hmac
import requests
import json
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)

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
    logging.info(f"Sending message to channel {channel}, thread {thread_ts}")
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
    logging.info(f"Slack API response: {response.json()}")
    return response.json()

def get_thread_messages(channel, thread_ts):
    """Get all messages in a thread"""
    logging.info(f"Getting thread messages for {channel}, {thread_ts}")
    url = "https://slack.com/api/conversations.replies"
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}
    params = {
        "channel": channel,
        "ts": thread_ts
    }
    response = requests.get(url, headers=headers, params=params)
    logging.info(f"Thread messages response: {response.json()}")
    return response.json()

@app.route('/')
def index():
    return 'Shipergy Deal Tracker Bot is running!'

@app.route('/slack/events', methods=['POST'])
def slack_events():
    slack_event = request.json
    logging.info(f"Received Slack event: {slack_event}")
    
    # Handle URL verification
    if 'challenge' in slack_event:
        return jsonify({'challenge': slack_event['challenge']})
    
    # Verify request
    if not verify_slack_request(request):
        logging.warning("Failed to verify Slack request")
        return 'Unauthorized', 403
    
    # Handle events
    if 'event' in slack_event:
        event = slack_event['event']
        logging.info(f"Event type: {event.get('type')}, Reaction: {event.get('reaction')}")
        
        # Handle reaction added
        if event.get('type') == 'reaction_added' and event.get('reaction') == 'x':
            logging.info(f"X reaction detected! Full event: {event}")
            channel = event['item']['channel']
            message_ts = event['item']['ts']
            user = event['user']
            
            logging.info(f"Channel: {channel}, Message TS: {message_ts}, User: {user}")
            
            # Get the thread messages
            thread_data = get_thread_messages(channel, message_ts)
            
            # Store thread data for later
            pending_key = f"{channel}_{message_ts}_{user}"
            pending_deals[pending_key] = {
                'channel': channel,
                'thread_ts': message_ts,
                'messages': thread_data.get('messages', []),
                'user': user
            }
            
            # Ask for Deal ID and Client
            response = send_slack_message(
                channel,
                "I see you've marked this deal as lost. Please provide:\n" +
                "• Deal ID (e.g., D-2024-0892)\n" +
                "• Client name (e.g., Adani Shipping)\n\n" +
                "Format: `D-2024-0892 | Adani Shipping`",
                message_ts
            )
            logging.info(f"Message sent response: {response}")
        
        # Handle message replies (looking for Deal ID)
        elif event.get('type') == 'message' and 'thread_ts' in event:
            # Skip if message is from a bot
            if 'bot_id' not in event and 'subtype' not in event:
                logging.info(f"Message in thread detected: {event.get('text')}")
                if 'D-2024' in event.get('text', ''):
                    logging.info("Deal ID found in message, processing...")
                    process_deal_details(event)
    
    return '', 200

def process_deal_details(event):
    """Process when user provides deal ID and client"""
    text = event['text']
    channel = event['channel']
    thread_ts = event['thread_ts']
    user = event['user']
    
    logging.info(f"Processing deal details: {text}")
    
    # Parse Deal ID and Client (expecting format: "D-2024-0892 | Adani Shipping")
    parts = text.replace('|', ' ').split()
    deal_id = None
    client_name = []
    
    for part in parts:
        if 'D-2024' in part:
            deal_id = part
        elif part and part != '|':
            client_name.append(part)
    
    client_name = ' '.join(client_name)
    
    logging.info(f"Parsed - Deal ID: {deal_id}, Client: {client_name}")
    
    if not deal_id or not client_name:
        send_slack_message(
            channel,
            "Please provide both Deal ID and Client name.\nFormat: `D-2024-0892 | Adani Shipping`",
            thread_ts
        )
        return
    
    # Find the pending deal data
    pending_key = None
    for key in pending_deals:
        if channel in key and thread_ts in key:
            pending_key = key
            break
    
    if not pending_key or pending_key not in pending_deals:
        logging.warning("Could not find pending deal data")
        send_slack_message(channel, "Sorry, I couldn't find the deal data. Please try again.", thread_ts)
        return
    
    thread_messages = pending_deals[pending_key]['messages']
    
    # Extract deal info using OpenAI
    deal_summary = extract_deal_with_openai(thread_messages, deal_id, client_name)
    
    # Format and send summary
    summary_text = format_deal_summary(deal_summary)
    send_slack_message(channel, summary_text, thread_ts)
    
    # Store the summary for later approval
    pending_deals[pending_key]['summary'] = deal_summary
    pending_deals[pending_key]['deal_id'] = deal_id
    pending_deals[pending_key]['client_name'] = client_name

def extract_deal_with_openai(messages, deal_id, client_name):
    """Use OpenAI to extract deal information"""
    logging.info(f"Extracting deal info with OpenAI for {deal_id}")
    
    # Format messages for OpenAI
    conversation = "\n".join([f"{msg.get('user', 'User')}: {msg.get('text', '')}" for msg in messages])
    
    # Call OpenAI API
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    
    prompt = f"""
    Extract the following details from this marine fuel bunker enquiry conversation:
    
    Conversation:
    {conversation}
    
    Known details:
    - Deal ID: {deal_id}
    - Client: {client_name}
    
    Extract and return as JSON:
    - vessel (vessel name)
    - imo (IMO number)
    - port
    - eta (arrival dates)
    - product (VLSFO/LSMGO/MGO etc - if multiple products, list them as a simple comma-separated string)
    - quantity (in MT - if multiple quantities, combine them)
    - our_price (our quoted price if mentioned, just the number)
    - competitor (competitor name)
    - competitor_price (competitor's price, just the number)
    - loss_reason (Price/Credit/Compliance - infer from context)
    - credit_terms (payment terms mentioned)
    
    If a field is not found, use "N/A".
    For the product field, return a simple string, not an array or object.
    Return only valid JSON, no additional text.
    """
    
    data = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a data extraction specialist for marine fuel trading deals."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1
    }
    
    try:
        response = requests.post(url, headers=headers, json=data)
        response_data = response.json()
        logging.info(f"OpenAI response: {response_data}")
        
        if 'choices' in response_data:
            extracted_text = response_data['choices'][0]['message']['content']
            # Parse the JSON response
            extracted_data = json.loads(extracted_text)
            
            # Fix product field if it's a list or dict
            if 'product' in extracted_data:
                product = extracted_data['product']
                if isinstance(product, list):
                    # Join list items into a string
                    extracted_data['product'] = ', '.join([str(p) for p in product])
                elif isinstance(product, dict):
                    # Extract product types and quantities
                    products = []
                    if 'type' in product:
                        products.append(str(product['type']))
                    else:
                        for key, value in product.items():
                            products.append(f"{key}: {value}")
                    extracted_data['product'] = ', '.join(products) if products else str(product)
                elif not isinstance(product, str):
                    extracted_data['product'] = str(product)
            
            # Clean up quantity field if needed
            if 'quantity' in extracted_data:
                quantity = extracted_data['quantity']
                if isinstance(quantity, list):
                    extracted_data['quantity'] = ', '.join([str(q) for q in quantity])
                elif isinstance(quantity, dict):
                    quantities = []
                    for key, value in quantity.items():
                        quantities.append(f"{value}")
                    extracted_data['quantity'] = ', '.join(quantities)
                elif not isinstance(quantity, str):
                    extracted_data['quantity'] = str(quantity)
            
            # Add the known details
            extracted_data['deal_id'] = deal_id
            extracted_data['client_name'] = client_name
            
            return extracted_data
        else:
            logging.error(f"OpenAI API error: {response_data}")
            # Return default structure if OpenAI fails
            return {
                'deal_id': deal_id,
                'client_name': client_name,
                'vessel': 'N/A',
                'imo': 'N/A',
                'port': 'N/A',
                'eta': 'N/A',
                'product': 'N/A',
                'quantity': 'N/A',
                'our_price': 'N/A',
                'competitor': 'N/A',
                'competitor_price': 'N/A',
                'loss_reason': 'N/A',
                'credit_terms': 'N/A'
            }
    except Exception as e:
        logging.error(f"OpenAI Error: {str(e)}")
        # Return default structure if error
        return {
            'deal_id': deal_id,
            'client_name': client_name,
            'vessel': 'Error extracting data',
            'imo': 'N/A',
            'port': 'N/A',
            'eta': 'N/A',
            'product': 'N/A',
            'quantity': 'N/A',
            'our_price': 'N/A',
            'competitor': 'N/A',
            'competitor_price': 'N/A',
            'loss_reason': 'N/A',
            'credit_terms': 'N/A'
        }

def format_deal_summary(summary):
    """Format the deal summary for Slack"""
    lines = [
        "📋 *DEAL SUMMARY - Please Verify*",
        "```",
        f"Deal ID:           {summary.get('deal_id', 'N/A')}",
        f"Client:            {summary.get('client_name', 'N/A')}",
        f"Vessel:            {summary.get('vessel', 'N/A')} (IMO: {summary.get('imo', 'N/A')})",
        f"Port:              {summary.get('port', 'N/A')}",
        f"ETA:               {summary.get('eta', 'N/A')}",
        f"Product:           {summary.get('product', 'N/A')}",
        f"Quantity:          {summary.get('quantity', 'N/A')}",
        f"Our Price:         ${summary.get('our_price', 'N/A')}",
        f"Competitor:        {summary.get('competitor', 'N/A')}",
        f"Competitor Price:  ${summary.get('competitor_price', 'N/A')}",
        f"Loss Reason:       {summary.get('loss_reason', 'N/A')}",
        f"Credit Terms:      {summary.get('credit_terms', 'N/A')}",
        "```",
        "Reply with ✅ to save to Airtable or ❌ to cancel."
    ]
    return "\n".join(lines)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
