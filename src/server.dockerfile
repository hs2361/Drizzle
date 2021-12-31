FROM python:3.10.1

EXPOSE 1234

WORKDIR /Drizzle/src

COPY ./server .
COPY ./exceptions.py .

RUN pip install pipenv
RUN pipenv install --system --deploy --ignore-pipfile

ENTRYPOINT [ "python", "server.py" ]
