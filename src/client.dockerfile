FROM python:3.10.1

EXPOSE 1234
EXPOSE 4321

WORKDIR /Drizzle/src

COPY ./client .
COPY ./utils ./utils

RUN pip install pipenv
RUN pipenv install --system --deploy --ignore-pipfile
RUN mkdir ../share
ARG file='./FAC Archive.zip'
COPY ${file} ../share/fac/

ENTRYPOINT [ "python", "client.py" ]
