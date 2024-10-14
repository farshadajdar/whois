from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.utils import formataddr, make_msgid
from re import T
# from gettext import dpgettext
# from shutil import ExecError
from flask import Flask, request, jsonify
import requests
import logging
import smtplib
# import whoisdomain as whois
import whois
import sys
import os

app = Flask(__name__)

current_directory = os.path.dirname(sys.executable)
logfile_path = os.path.join(current_directory, 'whois.log')

logging.basicConfig(
    filename=logfile_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def custom_whois(domains: list):
  results = {}
  for domain in domains:
    response = requests.get(f'{domain}')
    results[domain] = response
  return results

def get_whois(domains: list):
  try:
    results = {'result': {}}
    results['availableDomains'] = []
    for domain in domains:
      try:
        response = whois.whois(url=domain.lower())
        if response['domain_name'] is None:
          results['result'][domain] = {'status': ['tld not supported']}
        else:
          results['result'][domain] = response
      except Exception as e:
        # print(type(e.__str__()))
        if 'No match for' in e.__str__():
          results['result'][domain] = {'status': ['available for registration']}
          results['availableDomains'].append(domain)
        continue
    return results
  except Exception as e:
    logging.error(f'Get whois func error: ${e}')
    # raise ValueError("Get whois function occurred") from e

def send_email(results:dict, emails:list):
    try:
      if len(emails) > 0 and len(results['availableDomains']) > 0:
        sentToMails = []
        for email in emails:
          message = f"Current domains are available to register : {','.join(results['availableDomains'])}\n\n"

          for key in results['result']:
            value = results['result'][key]
            # print(f'Key => {key}')
            message += f'\n-------------\n{key}:\n'
            status = '  '
            for a in value['status']:
              status += f"{a.split(' htt')[0]}, "
            message += f"  Status: {status}\n"
            message += f"  Registrar: {value['registrar']}\n" if 'registrar' in value else ''
            message += f"  Creation_date: {value['creation_date']}\n" if 'creation_date' in value else ''
            message += (f"  Expiration_date: {value['expiration_date']}" if 'expiration_date' in value else '')
            # print(message)
          msg = MIMEMultipart()
          msg['From'] = 'whois@webnevisan.com'
          msg['To'] = email
          msg['Subject'] = 'Whois available domains'
          msg['Message-ID'] = make_msgid()
          msg.attach(MIMEText(message, 'plain'))
    
          server = smtplib.SMTP('mail.webnevisan.com', '587')
          server.starttls()
          server.login('whois@webnevisan.com', 'GiOWy__wuVHA')
    
          text = msg.as_string()
          server.sendmail('whois@webnevisan.com', email, text)
          server.quit()
          print(f'Mail has been sent to: {email}')
          sentToMails.append(email)
        return sentToMails
      
    except smtplib.SMTPRecipientsRefused:
        print("All recipients were refused. Nobody got the mail.")
    except smtplib.SMTPSenderRefused:
        print("The server didn't accept the sender address.")
    except smtplib.SMTPDataError:
        print("The server replied with an unexpected error code (other than a refusal).")
    except smtplib.SMTPException as e:
        print(f"Failed to send email: {e}")
    except Exception as e:
      print(e)


@app.route('/')
def home():
  logging.info(f'Welcome to whois service! from: {request.headers}')
  return "Welcome to whois service!"

@app.route('/whois', methods=['GET'])
def send_whois():
  try:
    # print(f'Request body => {request.json}')
    if request.headers.getlist("X-Forwarded-For"):
      logging.info(f'Request payload from ${request.headers.getlist("X-Forwarded-For")[0]}: {request.json}')
    else:
      logging.info(f'Request payload from ${request.remote_addr}: {request.json}')
    if 'domains' in request.json and request.json['domains'] != "":
      domains = request.json['domains']
      results = get_whois(domains)
      if 'emails' in request.json:
        emails = request.json['emails']
        results['sentToMails'] = send_email(results, emails)
        return jsonify({'status': 'success', 'result': results})
      else:
        return jsonify({'status': 'error', 'message': 'No email provided'})
    else:
      return jsonify({'status': 'error', 'message': 'No domain provided'})
  except Exception as e:
    print(f'Send whois error: {e}')
    logging.error(f'Send whois error: {e}')
    return jsonify({'status': 'error', 'message': f'{e}'})


if __name__ == '__main__':
  print('Service is running on port 2083')
  logging.info('Service is running on port 2083')
  app.run(host= '0.0.0.0', port=2083, debug=False, ssl_context=('/etc/ssl/certificates/cloudflare.crt', '/etc/ssl/certificates/cloudflare.key'))