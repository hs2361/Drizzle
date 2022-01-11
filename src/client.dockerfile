FROM python:3.10.1

EXPOSE 1234
EXPOSE 4321

WORKDIR /Drizzle/src

RUN rm -rf ./*
COPY ./client .
COPY ./utils ./utils

RUN pip install pipenv
RUN pipenv install --system --deploy --ignore-pipfile
RUN mkdir ../share
RUN fallocate -l 1G ../share/test.file

ENTRYPOINT [ "python", "client.py" ]
