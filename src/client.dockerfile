FROM python:3.10.1

EXPOSE 1234
EXPOSE 4321

WORKDIR /Drizzle/src

RUN rm -rf ./*
COPY ./client .
COPY ./utils ./utils
COPY ./share ../share

RUN pip install pipenv
RUN pipenv install --system --deploy --ignore-pipfile
# RUN mkdir ../share
RUN mkdir ../share/sub

RUN fallocate -l 1G ../share/test1.file
RUN fallocate -l 5M ../share/test2.file
RUN fallocate -l 5K ../share/sub/test3.file
RUN fallocate -l 100M ../share/sub/test4.file

ENTRYPOINT [ "python", "client.py" ]
