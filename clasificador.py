import os.path
import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neural_network import MLPClassifier
import pickle
import base64
from email.utils import parseaddr
from datetime import datetime
from dateutil import parser

# Configuración de Firebase
cred = credentials.Certificate("firebase_credentials.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': ''
})

# Obtener una referencia a la base de datos
ref = db.reference("/")

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.modify']
TOKEN = 'token.json'
CREDENTIALS = 'credentials.json'

def get_decoded_body(data):
    """Decodes the Base64 encoded message body."""
    try:
        body_bytes = base64.urlsafe_b64decode(data)
        body = body_bytes.decode('utf-8')
        return body
    except Exception as e:
        print(f'Error decoding message body: {e}')
        return None

def classify_text(text):
    # Cargar el modelo entrenado y el vectorizador desde los archivos
    with open('modelo_entrenado.pkl', 'rb') as file:
        classifier = pickle.load(file)
    with open('vectorizador.pkl', 'rb') as file:
        vectorizer = pickle.load(file)

    # Vectorizar el texto utilizando el vectorizador cargado
    text_vectorized = vectorizer.transform([text])

    # Realizar la clasificación utilizando el modelo cargado
    classification = classifier.predict(text_vectorized)

    return classification[0]

def move_message(service, user_id, msg_id, label_name):
    try:
        # Obtiene la información actual del mensaje
        msg = service.users().messages().get(userId=user_id, id=msg_id).execute()

        # Obtiene el ID de la etiqueta
        label_id = None
        labels = service.users().labels().list(userId=user_id).execute().get('labels', [])
        for label in labels:
            if label['name'] == label_name:
                label_id = label['id']
                break

        # Mueve el mensaje a la etiqueta correspondiente
        if label_id:
            service.users().messages().modify(userId=user_id, id=msg_id, body={'removeLabelIds': ['INBOX'], 'addLabelIds': [label_id]}).execute()
            print(f"Moved message to label '{label_name}': {msg_id}")
        else:
            print(f"Label '{label_name}' not found.")

    except HttpError as error:
        # TODO(developer) - Handle errors from Gmail API.
        print(f'An error occurred: {error}')

def main():
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists(TOKEN):
        creds = Credentials.from_authorized_user_file(TOKEN, SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open(TOKEN, 'w') as token:
            token.write(creds.to_json())

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], q='is:unread').execute()
        messages = results.get('messages', [])

        if not messages:
            print('No messages found in the inbox.')
            return

        print('Subject and Body of the emails in the inbox:')
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            headers = msg['payload']['headers']
            subject = None
            body = None
            email = None
            date = None
            for part in msg['payload']['parts']:
                if part.get('mimeType') == 'text/plain' and part.get('body') and part['body'].get('data'):
                    body_data = part['body']['data']
                    body = get_decoded_body(body_data)
                    break

            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value']
                if header['name'] == 'From':
                    _, email = parseaddr(header['value'])
                if header['name'] == 'Date':
                    raw_date = header['value']
                    date = parser.parse(raw_date)
                    date = date.strftime("%Y-%m-%d %H:%M:%S")

            if subject or body:
                classification_subject = classify_text(subject)
                classification_body = classify_text(body)
                print(f"Subject: {subject}")
                print(f"Classification (Subject): {classification_subject}")
                print(f"Classification (Body): {classification_body}")
                print(f"Body: {body}")

                # Mover el mensaje a la etiqueta correspondiente
                if classification_subject == 1 or classification_body == 1:
                    move_message(service, 'me', message['id'], 'spam_emails')
                    # Guardar en Firebase
                    email_data = {
                        'email': email,
                        'subject': subject,
                        'date': date
                    }
                    ref.push().set(email_data)
                else:
                    move_message(service, 'me', message['id'], 'valid_emails')
            else:
                print("Subject or Body not found for the email.")

    except HttpError as error:
        # TODO(developer) - Handle errors from Gmail API.
        print(f'An error occurred: {error}')


# Llamar a la función principal
main()
