FROM python:3.10.1

EXPOSE 1234

WORKDIR /Drizzle/src

RUN rm -rf ./*
COPY ./server .
COPY ./utils ./utils

RUN pip install pipenv
RUN pipenv install --system --deploy --ignore-pipfile

ENTRYPOINT [ "python", "server.py" ]
