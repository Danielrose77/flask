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
AIRTABLE_API_KEY = os.environ.get('AIRTABLE_API_KEY', '')
AIRTABLE_BASE_ID = os.environ.get('AIRTABLE_BASE_ID', 'app1c51qhCjqxsebs')

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
            
            # Check if we've already processed this reaction
            pending_key = f"{channel}_{message_ts}_{user}"
            if pending_key in pending_deals and pending_deals[pending_key].get('reaction_processed'):
                logging.info(f"Already processed this reaction: {pending_key}")
                return '', 200
            
            # Get the thread messages
            thread_data = get_thread_messages(channel, message_ts)
            
            # Store thread data for later
            pending_deals[pending_key] = {
                'channel': channel,
                'thread_ts': message_ts,
                'messages': thread_data.get('messages', []),
                'user': user,
                'reaction_processed': True
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
                text = event.get('text', '')
                
                # Check for Deal ID
                if 'D-2024' in text:
                    logging.info("Deal ID found in message, processing...")
                    process_deal_details(event)
                
                # Check for approval confirmation (checkmark emoji)
                elif '✅' in text:
                    logging.info("Approval detected, saving to Airtable...")
                    save_to_airtable(event)
    
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
    
    # Check if we've already sent a summary for this deal
    if pending_deals[pending_key].get('summary_sent'):
        logging.info("Summary already sent for this deal")
        return
    
    thread_messages = pending_deals[pending_key]['messages']
    
    # Extract deal info using OpenAI
    deal_summary = extract_deal_with_openai(thread_messages, deal_id, client_name)
    
    # Format and send summary
    summary_text = format_deal_summary(deal_summary)
    send_slack_message(channel, summary_text, thread_ts)
    
    # Mark summary as sent and store the summary for later approval
    pending_deals[pending_key]['summary_sent'] = True
    pending_deals[pending_key]['summary'] = deal_summary
    pending_deals[pending_key]['deal_id'] = deal_id
    pending_deals[pending_key]['client_name'] = client_name

def save_to_airtable(event):
    """Save the deal to Airtable when user confirms with checkmark"""
    channel = event['channel']
    thread_ts = event['thread_ts']
    user = event['user']
    
    # Find the pending deal with summary
    pending_key = None
    for key in pending_deals:
        if channel in key and thread_ts in key and 'summary' in pending_deals[key]:
            pending_key = key
            break
    
    if not pending_key:
        logging.warning("No pending deal summary found for Airtable save")
        send_slack_message(channel, "No deal summary found to save.", thread_ts)
        return
    
    deal_data = pending_deals[pending_key]['summary']
    
    # Create Airtable records
    success = create_airtable_records(deal_data)
    
    if success:
        send_slack_message(channel, "✅ Deal successfully saved to Airtable!", thread_ts)
        # Clear the pending deal
        del pending_deals[pending_key]
    else:
        send_slack_message(channel, "❌ Error saving to Airtable. Please check the logs.", thread_ts)

def create_airtable_records(deal_data):
    """Create records in Airtable following Gareth's structure"""
    if not AIRTABLE_API_KEY:
        logging.error("Airtable API key not configured")
        return False
    
    headers = {
        'Authorization': f'Bearer {AIRTABLE_API_KEY}',
        'Content-Type': 'application/json'
    }
    
    try:
        # Extract deal number from Deal ID (D-2024-0892 -> 892)
        deal_number = int(deal_data['deal_id'].split('-')[-1])
        
        # Parse credit terms to number (30 days -> 30)
        credit_days = 30  # default
        if deal_data.get('credit_terms'):
            if 'CIA' in deal_data['credit_terms'].upper():
                credit_days = 0
            else:
                # Extract number from string like "30 days" or "45 ddd"
                import re
                numbers = re.findall(r'\d+', deal_data['credit_terms'])
                if numbers:
                    credit_days = int(numbers[0])
        
        # Parse quantities and prices
        try:
            total_qty = float(deal_data.get('quantity', '50').replace('MT', '').replace(',', '').strip().split('-')[0])
        except:
            total_qty = 50
        
        try:
            competitor_price = float(deal_data.get('competitor_price', '0').replace('$', '').replace(',', '').split('/')[0])
        except:
            competitor_price = 0
        
        # Step 1: Create the Offer
        offer_data = {
            "records": [{
                "fields": {
                    "OfferID": deal_data['deal_id'],
                    "Created Record": datetime.now().strftime("%Y-%m-%d"),
                    "auto": deal_number,
                    "Payment terms": [credit_days],
                    "today": datetime.now().strftime("%Y-%m-%d"),
                    "Currency": ["$ USD"],
                    "Total MT": total_qty,
                    "Real Total Client": competitor_price * total_qty,
                    "Real Total Shipergy": competitor_price * total_qty,
                    "Profit Margin $": 0,
                    "Qty Average": total_qty,
                    "Enquiry Status": ["Dismissed Enquiry / Lost"],
                    "Invoice Date": [datetime.now().strftime("%Y-%m-%d")],
                    "Estimated MAX Total Client": competitor_price * total_qty,
                    "Estimated MAX Total Shipergy": competitor_price * total_qty,
                    "Estimated Avg Total Client": competitor_price * total_qty,
                    "Estimated AVG Total Shipergy copy": competitor_price * total_qty,
                    "Estimated Profit Margin $": 0,
                    "Total Qty (For stage purposes)": total_qty,
                    "linkURL": "",
                    "Seller=PS": ["Yes"],
                    "Product Families": [deal_data.get('product', 'VLSFO').split(',')[0].strip()],
                    "Type of Products": ["Main Product"],
                    "VAT": 0,
                    "TOTAL CLIENT WITH VAT": competitor_price * total_qty,
                    "Loss Reason": deal_data.get('loss_reason', 'Price'),
                    "Competitor": deal_data.get('competitor', 'N/A')
                }
            }]
        }
        
        offer_url = f'https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/Offers'
        offer_response = requests.post(offer_url, headers=headers, data=json.dumps(offer_data))
        offer_result = offer_response.json()
        
        if 'error' in offer_result:
            logging.error(f"Error creating Offer: {offer_result}")
            return False
        
        offer_record_id = offer_result['records'][0]['id']
        logging.info(f"Offer created: {offer_record_id}")
        
        # Step 2: Create the Enquiry
        enquiry_data = {
            "records": [{
                "fields": {
                    "Status": "Dismissed Enquiry / Lost",
                    "Enquiry Date": datetime.now().isoformat() + "Z",
                    "Vessel": deal_data.get('vessel', 'Unknown Vessel'),
                    "Port": deal_data.get('port', 'Unknown Port'),
                    "Client Payment Terms": credit_days,
                    "OfferID": [offer_record_id],
                    "Date Range From": datetime.now().strftime("%Y-%m-%d"),
                    "Date Range To": datetime.now().strftime("%Y-%m-%d"),
                    "Currency": "$ USD",
                    "Eligible For Borrowing": "No",
                    "Invoice Date": datetime.now().strftime("%Y-%m-%d"),
                    "CIA Deal": "Yes" if credit_days == 0 else "No",
                    "Record Type": "Bunkers",
                    "IMO": deal_data.get('imo', 'N/A'),
                    "ETA": deal_data.get('eta', 'N/A')
                }
            }]
        }
        
        enquiry_url = f'https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/Enquiries'
        enquiry_response = requests.post(enquiry_url, headers=headers, data=json.dumps(enquiry_data))
        enquiry_result = enquiry_response.json()
        
        if 'error' in enquiry_result:
            logging.error(f"Error creating Enquiry: {enquiry_result}")
            return False
        
        enquiry_record_id = enquiry_result['records'][0]['id']
        logging.info(f"Enquiry created: {enquiry_record_id}")
        
        return True
        
    except Exception as e:
        logging.error(f"Error creating Airtable records: {str(e)}")
        return False

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
    
    Extract and return as JSON following these IMPORTANT RULES:
    
    1. vessel (vessel name)
    2. imo (IMO number)
    3. port
    4. eta (arrival dates)
    5. product (VLSFO/LSMGO/MGO etc - if multiple products, list them as a simple comma-separated string)
    6. quantity (in MT - if multiple quantities, combine them)
    7. our_price (our quoted price if mentioned, just the number)
    8. competitor (NOTE: The offers in the thread are from SUPPLIERS not competitors. Look for mentions of actual competitors like "7seas", "Minerva", "NBCO", etc. who won the deal)
    9. competitor_price (the price from the actual competitor who won, not supplier offers)
    10. loss_reason (If no specific reason is given, default to "Price". Other reasons might be "Credit" or "Compliance")
    11. credit_terms (DEFAULT to "30 days" unless specifically stated otherwise. Look for terms like "CIA" (cash in advance), "45 days", "60 days", "45 ddd", "60 ddd" etc.)
    
    IMPORTANT BUSINESS LOGIC:
    - Credit terms: If not mentioned, use "30 days" as default
    - "ddd" means "days" in credit terms
    - Loss reason: If not explicitly stated, assume "Price"
    - Competitors are companies we lost the deal to (like 7seas, Minerva, NBCO), NOT suppliers offering us prices
    - CIA means "Cash in Advance"
    
    If a field is not found, use "N/A" except for credit_terms (use "30 days") and loss_reason (use "Price").
    For the product field, return a simple string, not an array or object.
    Return only valid JSON, no additional text.
    """
    
    data = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a data extraction specialist for marine fuel trading deals. You understand marine fuel trading terminology and business practices."},
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
                    extracted_data['product'] = ', '.join([str(p) for p in product])
                elif isinstance(product, dict):
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
            
            # Apply business logic defaults
            if extracted_data.get('credit_terms') == 'N/A' or not extracted_data.get('credit_terms'):
                extracted_data['credit_terms'] = '30 days'
            
            if extracted_data.get('loss_reason') == 'N/A' or not extracted_data.get('loss_reason'):
                extracted_data['loss_reason'] = 'Price'
            
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
                'loss_reason': 'Price',
                'credit_terms': '30 days'
            }
    except Exception as e:
        logging.error(f"OpenAI Error: {str(e)}")
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
            'loss_reason': 'Price',
            'credit_terms': '30 days'
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
