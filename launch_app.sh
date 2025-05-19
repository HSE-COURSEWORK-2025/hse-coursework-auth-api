export $(cat .env | grep -v '^#' | xargs)
python3 -u launcher.py