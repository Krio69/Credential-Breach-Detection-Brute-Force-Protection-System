import os
from django.core.wsgi import get_wsgi_application
from django.core.management import call_command

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

# Initialize application
application = get_wsgi_application()
app = application

# 1. Run migrations
try:
    call_command('migrate', '--noinput')
except Exception as e:
    print(f"Migration error: {e}")

# 2. Run collectstatic to fix the broken Admin CSS
try:
    call_command('collectstatic', '--noinput')
    print("Static files collected successfully.")
except Exception as e:
    print(f"Static collection error: {e}")