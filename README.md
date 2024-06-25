


## Running Local Development Server

### Set Up Virtual Environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

## Dependencies

Dependencies are managed inside the `requirements` folder.

### Install Packages and Dependencies:

```bash
pip install -r requirements/dev.txt
```

### Environment Variables:

Copy `sample.env` to `.env` and configure necessary environment variables like database credentials, API keys, etc.

### Initialize Database:

```bash
python manage.py migrate
```

### Run Development Server:

```bash
python manage.py runserver
```

### Access the Development Server:

Open your web browser and go to `http://127.0.0.1:8000/` to see the Django project running.
```

