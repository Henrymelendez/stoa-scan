from flask_mail import Mail, Message
from app import mail

def send_email(subject, recipient, text_body, html_body):
    msg = Message(subject=subject,
                  recipients=[recipient],
                  body=text_body,
                  html=html_body)
    mail.send(msg)