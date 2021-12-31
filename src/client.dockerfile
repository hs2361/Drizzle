FROM python:3.10.1

EXPOSE 1234
EXPOSE 4321

WORKDIR /Drizzle/src

COPY ./client .
COPY ./exceptions.py .

RUN pip install pipenv
RUN pipenv install --system --deploy --ignore-pipfile

ENTRYPOINT [ "python", "client.py" ]
