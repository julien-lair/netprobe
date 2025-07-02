# Utilise une image Python légère
FROM python:3.11-slim

# Crée un répertoire de travail dans le conteneur
WORKDIR /app

# Copie les fichiers nécessaires
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Lance le serveur Python
CMD ["python", "-u", "main.py"]
