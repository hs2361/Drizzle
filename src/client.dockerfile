FROM python:3.10.1

EXPOSE 1234
EXPOSE 4321

WORKDIR /Drizzle/src

COPY ./client .
COPY ./utils ./utils

RUN pip install pipenv
RUN pipenv install --system --deploy --ignore-pipfile
RUN mkdir ../share
RUN echo "Hello" > ../share/hello.txt
RUN mkdir ../share/sub
RUN echo "Hello from the inside" > ../share/sub/hello2.txt

ENTRYPOINT [ "python", "client.py" ]
