``` bash
python -m pip install -r requirements.txt
```
``` bash
python manage.py makemigrations app1 --merge
```
```bash
python manage.py migrate

python manage.py migrate --run-syncdb 
```
- Create Super Admin account
```bash
python manage.py createsuperuser
```

-To Run the server
```bash
python manage.py runserver
```
