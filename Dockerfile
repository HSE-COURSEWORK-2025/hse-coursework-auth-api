FROM python:3.10.14-bookworm

WORKDIR /code


RUN pip3 install --upgrade pip
COPY ./requirements.txt /code/requirements.txt
RUN pip3 install -r requirements.txt

COPY . /code/
COPY ./launch_app.sh /launch_app.sh

EXPOSE 8080

ENTRYPOINT ["sh", "/launch_app.sh"]