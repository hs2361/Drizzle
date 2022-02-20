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

RUN fallocate -l 5M ../share/test2.file
RUN fallocate -l 5K ../share/sub/test3.file
RUN fallocate -l 1G ../share/sub/test1.file
RUN fallocate -l 100M ../share/sub/test4.file
RUN fallocate -l 10M ../share/sub/test5.file

RUN apt-get update
RUN apt-get install -y xauth

EXPOSE 8887

RUN xauth add legion/unix:  MIT-MAGIC-COOKIE-1  50258766dfae525d25243e9de1c92ff1

# ENTRYPOINT [ "python", "app.py" ]
